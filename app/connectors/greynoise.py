"""GreyNoise connector.

Two API plans are supported transparently:

* Community plan (no key required for ``/ip/basic/{ip}`` but we still gate on
  configuration to keep behaviour predictable) - classification only.
* Enterprise/Rapid7 InsightIDR key - richer ``/ip/context/{ip}`` response with
  actor, categories and first/last-seen timestamps.

GreyNoise distinguishes *background internet noise* (benign scanning) from
targeted malicious activity; the analyst summary uses that distinction.
"""

from __future__ import annotations

from typing import Any

from app.connectors.base import BaseConnector
from app.core.ioc import IOCType, ValidatedIOC
from app.core.models import EnrichmentResult, ProviderStatus

_COMMUNITY = "https://api.greynoise.io/v3/community/{ip}"
_ENTERPRISE = "https://api.enterprise.greynoise.io/greynoise/api/v3/{ip}"

_SUPPORTED = frozenset({IOCType.IPV4, IOCType.IPV6})

#: Classifications considered low-risk / informational by GreyNoise itself.
_BENIGN_CLASSIFICATIONS = {"benign", "unknown"}


class GreyNoiseConnector(BaseConnector):
    """Normalises GreyNoise classification into tri-state verdicts."""

    name = "greynoise"
    display_name = "GreyNoise"
    supported_types = _SUPPORTED

    @property
    def _enterprise(self) -> bool:
        # Keys prefixed with a dot are Rapid7 InsightIDs (community style);
        # any configured key is treated as enterprise-capable context data.
        return self.configured

    def _lookup(self, ioc: ValidatedIOC) -> EnrichmentResult:
        url = (_ENTERPRISE if self._enterprise else _COMMUNITY).format(ip=ioc.value)
        headers: dict[str, str] = {}
        if self._enterprise:
            headers["key"] = self._api_key

        payload = self._request_json("GET", url, headers=headers)

        if payload.get("__not_found__"):
            return EnrichmentResult(
                provider=self.name,
                status=ProviderStatus.NO_DATA,
                summary="IP not observed by GreyNoise sensors",
            )

        classification = str(payload.get("classification") or "").lower()
        actor = payload.get("actor") or payload.get("name")
        categories = payload.get("categories") or []
        if isinstance(categories, str):
            categories = [categories]
        org = payload.get("org") or payload.get("organization")
        country = payload.get("country_name") or payload.get("country")
        first_seen = payload.get("first_seen")
        last_seen = payload.get("seen_last") or payload.get("last_seen")
        noise = bool(payload.get("noise")) if isinstance(payload.get("noise"), bool) else None

        confidence, malicious = self._verdict(classification, noise)

        bits = [f"Classification: {classification or 'unknown'}"]
        if actor:
            bits.append(f"Actor: {actor}")
        if categories:
            bits.append("Categories: " + ", ".join(str(c) for c in categories[:5]))
        if noise is True:
            bits.append("observed as widespread background scanning (noise)")

        details = {
            "classification": classification or None,
            "actor": actor,
            "categories": categories,
            "organization": org,
            "country": country,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "noise": noise,
        }

        return EnrichmentResult(
            provider=self.name,
            status=ProviderStatus.OK,
            confidence=confidence,
            malicious=malicious,
            summary="; ".join(bits),
            details={k: v for k, v in details.items() if v not in (None, "", [])},
            raw_ref=f"https://www.greynoise.io/viz/address/{ioc.value}",
        )

    @staticmethod
    def _verdict(classification: str, noise: Any) -> tuple[int, Any]:
        """Map GreyNoise classification to (confidence, malicious verdict)."""
        if classification == "malicious":
            return 80, True
        if classification == "suspicious":
            return 40, None
        if classification in _BENIGN_CLASSIFICATIONS:
            return 10, False
        return 0, None
