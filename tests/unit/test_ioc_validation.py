"""Unit tests for the IOC validation engine (app.core.ioc)."""

from __future__ import annotations

import pytest

from app.core.ioc import (
    IOCType,
    extract_network_target,
    validate_ioc,
    validate_many,
)

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------- #
# IPv4
# --------------------------------------------------------------------------- #


class TestIPv4:
    def test_valid_public_ipv4(self) -> None:
        result = validate_ioc("8.8.8.8")
        assert result.valid
        assert result.ioc_type is IOCType.IPV4
        assert result.metadata["is_private"] is False
        assert result.metadata["is_reserved"] is False
        assert result.metadata["is_global"] is True

    def test_private_ipv4_detected(self) -> None:
        for value in ("192.168.1.10", "10.0.0.1", "172.16.5.5"):
            result = validate_ioc(value)
            assert result.valid and result.ioc_type is IOCType.IPV4, value
            assert result.metadata["is_private"] is True, value

    def test_reserved_ipv4_detected(self) -> None:
        result = validate_ioc("240.0.0.1")
        assert result.valid
        assert result.metadata["is_reserved"] is True

    def test_loopback_detected(self) -> None:
        result = validate_ioc("127.0.0.1")
        assert result.valid
        assert result.metadata["is_loopback"] is True

    @pytest.mark.parametrize(
        "bad",
        ["256.1.1.1", "1.1.1", "0177.0.0.1", "1.2.3.4.5", "8.8.8.8/24", "not.an.ip", "999.999.999.999"],
    )
    def test_invalid_ipv4_rejected(self, bad: str) -> None:
        result = validate_ioc(bad)
        # Invalid IPs must not be misclassified as IPV4 (may fall to unknown/domain-shaped).
        assert result.ioc_type is not IOCType.IPV4 or not result.valid
        if not result.valid:
            assert result.reason


# --------------------------------------------------------------------------- #
# IPv6
# --------------------------------------------------------------------------- #


class TestIPv6:
    def test_full_ipv6(self) -> None:
        result = validate_ioc("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert result.valid and result.ioc_type is IOCType.IPV6

    def test_compressed_ipv6(self) -> None:
        result = validate_ioc("2001:db8::1")
        assert result.valid and result.ioc_type is IOCType.IPV6
        assert result.metadata["version"] == 6

    def test_ipv6_loopback(self) -> None:
        result = validate_ioc("::1")
        assert result.valid and result.metadata["is_loopback"] is True

    def test_invalid_ipv6(self) -> None:
        result = validate_ioc("2001:db8:::1")
        assert not result.valid or result.ioc_type is not IOCType.IPV6


# --------------------------------------------------------------------------- #
# Domains
# --------------------------------------------------------------------------- #


class TestDomains:
    @pytest.mark.parametrize(
        "value",
        ["example.com", "malicious-domain.com", "sub.domain.example.co.uk", "a-b.example.org"],
    )
    def test_valid_domains(self, value: str) -> None:
        result = validate_ioc(value)
        assert result.valid and result.ioc_type is IOCType.DOMAIN, value
        assert result.value == value.lower()

    @pytest.mark.parametrize(
        "value",
        ["-bad.com", "bad-.com", "no_tld", ".leading-dot.com", "toolonglabel" * 5 + ".com", "example.c"],
    )
    def test_invalid_domains(self, value: str) -> None:
        result = validate_ioc(value)
        assert not result.valid or result.ioc_type is not IOCType.DOMAIN, value

    def test_domain_case_normalised(self) -> None:
        assert validate_ioc("EXAMPLE.COM").value == "example.com"


# --------------------------------------------------------------------------- #
# URLs
# --------------------------------------------------------------------------- #


class TestURLs:
    def test_https_url(self) -> None:
        result = validate_ioc("https://evil.example.com/payload?x=1")
        assert result.valid and result.ioc_type is IOCType.URL
        assert result.metadata["host"] == "evil.example.com"
        assert result.metadata["scheme"] == "https"
        assert result.metadata["port"] == 443

    def test_url_with_ip_host_and_port(self) -> None:
        result = validate_ioc("http://203.0.113.5:8080/stage/bin")
        assert result.valid and result.ioc_type is IOCType.URL
        assert result.metadata["host"] == "203.0.113.5"
        assert result.metadata["port"] == 8080

    def test_ftp_scheme_allowed(self) -> None:
        assert validate_ioc("ftp://files.example.com/pub").valid

    @pytest.mark.parametrize("value", ["javascript:alert(1)", "file:///etc/passwd", "data:text/html,x"])
    def test_dangerous_schemes_rejected(self, value: str) -> None:
        result = validate_ioc(value)
        assert not result.valid
        assert "scheme" in result.reason or "unrecognised" in result.reason

    def test_url_without_host_rejected(self) -> None:
        result = validate_ioc("http:///just-a-path")
        assert not result.valid

    def test_bare_url_no_scheme_is_not_url(self) -> None:
        result = validate_ioc("evil.example.com/path")
        assert result.ioc_type is not IOCType.URL  # treated as invalid/domain-shaped input


# --------------------------------------------------------------------------- #
# Hashes
# --------------------------------------------------------------------------- #


class TestHashes:
    MD5 = "d41d8cd98f00b204e9800998ecf8427e"
    SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_md5(self) -> None:
        result = validate_ioc(self.MD5)
        assert result.valid and result.ioc_type is IOCType.MD5

    def test_sha1(self) -> None:
        result = validate_ioc(self.SHA1)
        assert result.valid and result.ioc_type is IOCType.SHA1

    def test_sha256(self) -> None:
        result = validate_ioc(self.SHA256)
        assert result.valid and result.ioc_type is IOCType.SHA256

    def test_hashes_case_insensitive_and_normalised(self) -> None:
        result = validate_ioc(self.MD5.upper())
        assert result.valid and result.ioc_type is IOCType.MD5
        assert result.value == self.MD5

    def test_wrong_length_hex_is_not_hash(self) -> None:
        result = validate_ioc("d41d8cd98f00b204e9800998ecf8427")  # 31 chars
        assert result.ioc_type is not IOCType.MD5


# --------------------------------------------------------------------------- #
# Emails
# --------------------------------------------------------------------------- #


class TestEmails:
    def test_valid_email(self) -> None:
        result = validate_ioc("Phishing.Attack@Evil-Example.com")
        assert result.valid and result.ioc_type is IOCType.EMAIL
        assert result.value == "phishing.attack@evil-example.com"
        assert result.metadata["domain"] == "evil-example.com"

    @pytest.mark.parametrize("value", ["plain-addr", "@no-local.com", "a@b", "two@@ats.com"])
    def test_invalid_emails(self, value: str) -> None:
        assert not validate_ioc(value).valid or validate_ioc(value).ioc_type is not IOCType.EMAIL


# --------------------------------------------------------------------------- #
# Hostile / malformed inputs
# --------------------------------------------------------------------------- #


class TestHostileInputs:
    def test_empty_string(self) -> None:
        result = validate_ioc("")
        assert not result.valid and "empty" in result.reason

    def test_whitespace_only(self) -> None:
        assert not validate_ioc("   ").valid

    def test_control_characters_rejected(self) -> None:
        result = validate_ioc("8.8.8.8\n")  # trailing newline stripped -> valid IP
        assert result.valid
        hostile = validate_ioc("8.8.8.\x008")
        assert not hostile.valid
        assert "control characters" in hostile.reason

    def test_overlong_input_rejected(self) -> None:
        result = validate_ioc("a" * 5000)
        assert not result.valid
        assert "maximum length" in result.reason

    def test_non_string_input(self) -> None:
        result = validate_ioc(12345)  # type: ignore[arg-type]
        assert not result.valid

    def test_validation_never_raises(self) -> None:
        for payload in ["<script>alert(1)</script>", "' OR 1=1 --", "../../etc/passwd", "\x1b[31m"]:
            result = validate_ioc(payload)  # must not raise
            assert isinstance(result.valid, bool)


# --------------------------------------------------------------------------- #
# Bulk helpers
# --------------------------------------------------------------------------- #


class TestBulkHelpers:
    def test_validate_many_partitions_and_dedupes(self) -> None:
        values = ["8.8.8.8", "8.8.8.8", "bogus!!", "example.com", "", "https://a.b/c"]
        valid, invalid = validate_many(values)
        assert {v.value for v in valid} == {"8.8.8.8", "example.com", "https://a.b/c"}
        assert len(valid) == 3  # duplicate collapsed
        assert any(not v.valid for v in invalid)
        assert all(not v.valid for v in invalid)

    def test_extract_network_target(self) -> None:
        assert extract_network_target(validate_ioc("8.8.8.8")) == "8.8.8.8"
        assert extract_network_target(validate_ioc("example.com")) == "example.com"
        url = validate_ioc("https://cdn.evil.test/x.sh")
        assert extract_network_target(url) == "cdn.evil.test"
        md5 = validate_ioc("d41d8cd98f00b204e9800998ecf8427e")
        assert extract_network_target(md5) is None
