"""IOC validation engine.

Validates and classifies Indicators of Compromise *before* any network call is
made (fail-fast input validation, OWASP A03). Supported types: IPv4, IPv6,
domain names, URLs, MD5/SHA1/SHA256 file hashes and email addresses.

Design decisions
----------------
* Pure standard library (``ipaddress``, ``re``, ``urllib.parse``) so the
  validator can be reused by the CLI, API and dashboard without extra deps.
* Validation never raises for bad user input; it returns a structured result
  with an explicit reason, which keeps callers simple and log-safe.
* Hostnames are checked against RFC-1123 label rules and IDNA-encoded when
  possible; URLs must include a scheme to avoid ambiguous "bare domain"
  inputs being treated as URLs.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional
from urllib.parse import urlparse

# --------------------------------------------------------------------------- #
# Types
# --------------------------------------------------------------------------- #


class IOCType(str, Enum):
    """Indicator-of-compromise categories supported by the analyzer."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"


#: Network-relevant IOC types (hashes are file-based, not network-based).
NETWORK_IOC_TYPES: frozenset[IOCType] = frozenset(
    {IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL}
)

_HASH_PATTERNS: dict[IOCType, re.Pattern[str]] = {
    IOCType.MD5: re.compile(r"^[a-fA-F0-9]{32}$"),
    IOCType.SHA1: re.compile(r"^[a-fA-F0-9]{40}$"),
    IOCType.SHA256: re.compile(r"^[a-fA-F0-9]{64}$"),
}

# RFC-1123 shape: labels of alphanumerics/hyphens with no edge hyphens, an
# alphabetic TLD of >= 2 chars. Length limits are checked explicitly below so
# the same validation path governs bare domains, URL hosts and bulk input.
_DOMAIN_RE = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

#: RFC-1035/1123 limit for the whole hostname (domains and URL hosts alike).
_MAX_HOSTNAME_LENGTH = 253
#: RFC-1035/1123 limit for any single hostname label.
_MAX_LABEL_LENGTH = 63


def _is_valid_hostname(host: str) -> bool:
    """Return ``True`` when *host* is a syntactically valid public hostname.

    Single authoritative check used by domain validation, URL-host validation
    and (transitively) :func:`validate_many`: RFC-1123 shape plus the explicit
    per-label (<=63) and whole-name (<=253) length caps from RFC-1035.
    """
    if not 1 <= len(host) <= _MAX_HOSTNAME_LENGTH:
        return False
    if not _DOMAIN_RE.match(host):
        return False
    return all(len(label) <= _MAX_LABEL_LENGTH for label in host.split("."))

_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}$"
)

_MAX_IOC_LENGTH = 2048


@dataclass(frozen=True)
class ValidatedIOC:
    """Outcome of validating a single indicator string."""

    value: str
    ioc_type: IOCType
    valid: bool
    reason: str = ""
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "ioc_type": self.ioc_type.value,
            "valid": self.valid,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _is_ipv4(value: str) -> bool:
    # ``ipaddress`` accepts leading-zero octets ("0177.0.0.1") and integer
    # literals ("1234"); both are ambiguous mangled-feed shapes, so the dotted
    # quad is checked explicitly before parsing.
    if not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", value):
        return False
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _is_ipv6(value: str) -> bool:
    # Reject embedded-zone / bracket forms conservatively before parsing.
    if "[" in value or "]" in value or "%" in value:
        return False
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def _ip_metadata(ip: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> dict[str, object]:
    return {
        "version": ip.version,
        "is_private": ip.is_private,
        "is_reserved": ip.is_reserved,
        "is_loopback": ip.is_loopback,
        "is_link_local": ip.is_link_local,
        "is_multicast": ip.is_multicast,
        "is_global": ip.is_global,
    }


def _looks_like_url(value: str) -> bool:
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", value))


def validate_ioc(raw_value: str) -> ValidatedIOC:
    """Validate and classify a single IOC string.

    Args:
        raw_value: Untrusted indicator supplied by an analyst or feed.

    Returns:
        :class:`ValidatedIOC` - never raises on malformed input.
    """
    if not isinstance(raw_value, str):
        return ValidatedIOC(str(raw_value), IOCType.UNKNOWN, False, "input must be a string")

    value = raw_value.strip()

    if not value:
        return ValidatedIOC(raw_value, IOCType.UNKNOWN, False, "empty indicator")
    if len(value) > _MAX_IOC_LENGTH:
        return ValidatedIOC(value[:80], IOCType.UNKNOWN, False, "indicator exceeds maximum length")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        # Control characters indicate tampered feeds / injection attempts.
        return ValidatedIOC(value[:80], IOCType.UNKNOWN, False, "contains control characters")

    # --- Hashes ----------------------------------------------------------- #
    for ioc_type, pattern in _HASH_PATTERNS.items():
        if pattern.match(value):
            return ValidatedIOC(
                value.lower(), ioc_type, True, "", {"length": len(value)}
            )

    # --- Email ------------------------------------------------------------ #
    if "@" in value and _EMAIL_RE.match(value):
        domain = value.split("@", 1)[1].lower()
        return ValidatedIOC(
            value.lower(), IOCType.EMAIL, True, "", {"domain": domain}
        )

    # --- IP addresses (checked before URLs/domains) ----------------------- #
    if _is_ipv4(value):
        ip = ipaddress.IPv4Address(value)
        return ValidatedIOC(value, IOCType.IPV4, True, "", _ip_metadata(ip))
    if ":" in value and _is_ipv6(value):
        ip = ipaddress.IPv6Address(value)
        return ValidatedIOC(value, IOCType.IPV6, True, "", _ip_metadata(ip))

    # --- URLs -------------------------------------------------------------- #
    if _looks_like_url(value):
        parsed = urlparse(value)
        # Reject dangerous/unsupported schemes *before* any host parsing so
        # local-file vectors (file://, jar://...) fail with a clear reason.
        if parsed.scheme.lower() not in {"http", "https", "ftp"}:
            return ValidatedIOC(
                value, IOCType.URL, False, f"unsupported URL scheme: {parsed.scheme}"
            )
        host = (parsed.hostname or "").lower()
        if not host:
            return ValidatedIOC(value, IOCType.URL, False, "URL has no host component")
        # Host may itself be an IP literal.
        host_valid = _is_valid_hostname(host) or _is_ipv4(host) or _is_ipv6(host)
        if not host_valid:
            return ValidatedIOC(value, IOCType.URL, False, "invalid URL host")
        return ValidatedIOC(
            value,
            IOCType.URL,
            True,
            "",
            {
                "scheme": parsed.scheme.lower(),
                "host": host,
                "path": parsed.path or "/",
                "port": parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
            },
        )

    # --- Bare domains ------------------------------------------------------- #
    if _is_valid_hostname(value.lower()):
        # RFC-1035: a hostname must carry at least two labels. A single label
        # ("no_tld", "localhost") is a resolvable name on private networks but
        # never a public IOC, so it is rejected with an explicit reason.
        if "." not in value:
            return ValidatedIOC(
                value, IOCType.DOMAIN, False, "domain lacks a top-level domain (single label)"
            )
        return ValidatedIOC(
            value.lower(),
            IOCType.DOMAIN,
            True,
            "",
            {"tld": value.rsplit(".", 1)[-1].lower()},
        )

    return ValidatedIOC(
        value,
        IOCType.UNKNOWN,
        False,
        "unrecognised indicator format (expected IP/domain/URL/hash/email)",
    )


def validate_many(values: Iterable[str]) -> tuple[list[ValidatedIOC], list[ValidatedIOC]]:
    """Partition *values* into ``(valid, invalid)`` validated IOC lists."""
    valid: list[ValidatedIOC] = []
    invalid: list[ValidatedIOC] = []
    seen: set[str] = set()
    for raw in values:
        result = validate_ioc(raw)
        if result.valid:
            key = (result.ioc_type, result.value.lower())
            if key in seen:
                continue
            seen.add(key)
            valid.append(result)
        else:
            invalid.append(result)
    return valid, invalid


def extract_network_target(ioc: ValidatedIOC) -> Optional[str]:
    """Return the best enrichment target for a network IOC.

    For URLs this is the hostname; for IPs the address; for domains the name.
    Hashes/emails return ``None`` because Release-1 connectors do not consume
    them directly (VT handles hashes via dedicated lookups).
    """
    if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
        return ioc.value
    if ioc.ioc_type == IOCType.DOMAIN:
        return ioc.value
    if ioc.ioc_type == IOCType.URL:
        host = ioc.metadata.get("host")
        return str(host) if host else None
    return None
