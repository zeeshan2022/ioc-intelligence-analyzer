"""Unit tests for threat-intelligence connectors.

All HTTP traffic is mocked via the ``FakeSession`` double - no test ever calls
a real provider API. Tests cover: normalisation, retry behaviour, timeout and
429 rate-limit handling, authentication errors, and error-status mapping.
"""

from __future__ import annotations

import requests

import pytest

from app.connectors.abuseipdb import AbuseIPDBConnector
from app.connectors.base import BaseConnector
from app.connectors.greynoise import GreyNoiseConnector
from app.connectors.virustotal import VirusTotalConnector
from app.core.ioc import IOCType, validate_ioc
from app.core.models import ProviderStatus

from tests.conftest import FakeResponse, FakeSession, make_ioc

pytestmark = pytest.mark.unit


def _connector(cls, api_key, session, settings):
    return cls(api_key, settings, session=session)


# --------------------------------------------------------------------------- #
# VirusTotal
# --------------------------------------------------------------------------- #


class TestVirusTotalConnector:
    def test_ip_lookup_normalised(self, fast_settings) -> None:
        payload = {
            "data": {
                "id": "ip-203.0.113.66",
                "attributes": {
                    "last_analysis_stats": {"malicious": 12, "suspicious": 2, "harmless": 58},
                    "last_analysis_results": {
                        "Kaspersky": {"category": "malicious", "result": "Trojan.Win32.Generic"},
                        "ESET": {"category": "clean", "result": None},
                    },
                    "country": "NL",
                    "as_owner": "DEMO-ISP",
                },
                "links": {"self": "https://www.virustotal.com/api/v3/ip_addresses/203.0.113.66"},
            }
        }
        session = FakeSession([FakeResponse(200, payload)])
        connector = _connector(VirusTotalConnector, "vt-key", session, fast_settings)

        result = connector.enrich(validate_ioc("203.0.113.66"))

        assert result.status is ProviderStatus.OK
        assert result.malicious is True
        assert result.confidence > 0
        assert "12" in result.summary
        assert "Trojan.Win32.Generic" in result.details["malicious_detectors"]
        # Auth header used correctly (x-apikey per VT v3 docs).
        assert session.calls[0]["headers"]["x-apikey"] == "vt-key"
        assert "/ip_addresses/203.0.113.66" in session.calls[0]["url"]

    def test_hash_endpoint_routing(self, fast_settings) -> None:
        session = FakeSession([FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "harmless": 70}}}})])
        connector = _connector(VirusTotalConnector, "k", session, fast_settings)
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        connector.enrich(validate_ioc(md5))
        assert f"/files/{md5}" in session.calls[0]["url"]

    def test_url_uses_base64_id(self, fast_settings) -> None:
        import base64

        session = FakeSession([FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}})])
        connector = _connector(VirusTotalConnector, "k", session, fast_settings)
        url = "https://evil.example.com/payload.exe"
        connector.enrich(validate_ioc(url))
        expected_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        assert f"/urls/{expected_id}" in session.calls[0]["url"]

    def test_404_maps_to_no_data(self, fast_settings) -> None:
        session = FakeSession([FakeResponse(404, {})])
        connector = _connector(VirusTotalConnector, "k", session, fast_settings)
        result = connector.enrich(validate_ioc("example.com"))
        assert result.status is ProviderStatus.NO_DATA

    def test_email_type_skipped(self, fast_settings) -> None:
        session = FakeSession([])
        connector = _connector(VirusTotalConnector, "k", session, fast_settings)
        result = connector.enrich(validate_ioc("phish@evil.example.com"))
        assert result.status is ProviderStatus.SKIPPED
        assert session.calls == []

    def test_missing_api_key_is_configuration_error(self, fast_settings) -> None:
        connector = _connector(VirusTotalConnector, None, FakeSession([]), fast_settings)
        result = connector.enrich(validate_ioc("8.8.8.8"))
        assert result.status is ProviderStatus.CONFIGURATION_ERROR
        assert "API key" in (result.error or "")

    def test_401_maps_to_authentication_error_no_retry(self, fast_settings) -> None:
        session = FakeSession([FakeResponse(401, {})])
        connector = _connector(VirusTotalConnector, "bad-key", session, fast_settings)
        result = connector.enrich(validate_ioc("8.8.8.8"))
        assert result.status is ProviderStatus.AUTHENTICATION_ERROR
        assert len(session.calls) == 1  # terminal auth errors are not retried

    def test_malformed_json_maps_to_parse_error(self, fast_settings) -> None:
        session = FakeSession([FakeResponse(200, raise_json_error=True)])
        connector = _connector(VirusTotalConnector, "k", session, fast_settings)
        result = connector.enrich(validate_ioc("8.8.8.8"))
        assert result.status is ProviderStatus.PARSE_ERROR


# --------------------------------------------------------------------------- #
# AbuseIPDB
# --------------------------------------------------------------------------- #


class TestAbuseIPDBConnector:
    def _payload(self, **overrides) -> dict:
        data = {
            "ipAddress": "198.51.100.9",
            "abuseConfidenceScore": 87,
            "totalReports": 33,
            "numDistinctReports": 12,
            "blacklistCategories": [{"id": 8, "nameCode": "Botnet", "name": "Botnet"},
                                     {"id": 18, "nameCode": "Malicious Host", "name": "Malicious Host"}],
            "countryCode": "RU",
            "isp": "Evil Hosting Ltd",
            "isWhitelisted": False,
            "isTor": False,
            "lastReportedAt": "2026-10-01T00:00:00+00:00",
        }
        data.update(overrides)
        return {"data": data}

    def test_confidence_and_severe_categories(self, fast_settings) -> None:
        session = FakeSession([FakeResponse(200, self._payload())])
        connector = _connector(AbuseIPDBConnector, "aidb-key", session, fast_settings)
        result = connector.enrich(validate_ioc("198.51.100.9"))

        assert result.status is ProviderStatus.OK
        assert result.confidence == 87
        assert result.malicious is True
        assert "Botnet" in result.details["severe_categories"]
        assert result.details["is_tor"] in (False, None) or result.details.get("is_tor") is not True
        assert session.calls[0]["headers"]["Key"] == "aidb-key"
        assert session.calls[0]["params"]["ipAddress"] == "198.51.100.9"

    def test_whitelisted_address_benign(self, fast_settings) -> None:
        session = FakeSession([FakeResponse(200, self._payload(isWhitelisted=True, abuseConfidenceScore=0, totalReports=0))])
        connector = _connector(AbuseIPDBConnector, "k", session, fast_settings)
        result = connector.enrich(validate_ioc("198.51.100.9"))
        assert result.malicious is False

    def test_domain_not_supported(self, fast_settings) -> None:
        connector = _connector(AbuseIPDBConnector, "k", FakeSession([]), fast_settings)
        result = connector.enrich(validate_ioc("example.com"))
        assert result.status is ProviderStatus.SKIPPED


# --------------------------------------------------------------------------- #
# GreyNoise
# --------------------------------------------------------------------------- #


class TestGreyNoiseConnector:
    def test_malicious_classification(self, fast_settings) -> None:
        payload = {
            "ip": "198.51.100.23",
            "classification": "malicious",
            "actor": "censys-scanner",
            "categories": ["scanner"],
            "org": "EvilNet",
            "country_name": "CN",
            "seen_last": "2026-10-28T10:00:00Z",
        }
        session = FakeSession([FakeResponse(200, payload)])
        connector = _connector(GreyNoiseConnector, "gn-key", session, fast_settings)
        result = connector.enrich(validate_ioc("198.51.100.23"))

        assert result.status is ProviderStatus.OK
        assert result.malicious is True
        assert result.confidence == 80
        assert result.details["classification"] == "malicious"
        assert session.calls[0]["headers"]["key"] == "gn-key"

    def test_benign_noise_verdict(self, fast_settings) -> None:
        payload = {"ip": "1.2.3.4", "classification": "benign", "noise": True}
        session = FakeSession([FakeResponse(200, payload)])
        connector = _connector(GreyNoiseConnector, "gn", session, fast_settings)
        result = connector.enrich(validate_ioc("1.2.3.4"))
        assert result.malicious is False
        assert "noise" in result.summary.lower()

    def test_404_not_observed(self, fast_settings) -> None:
        session = FakeSession([FakeResponse(404, {})])
        connector = _connector(GreyNoiseConnector, "gn", session, fast_settings)
        result = connector.enrich(validate_ioc("1.2.3.4"))
        assert result.status is ProviderStatus.NO_DATA


# --------------------------------------------------------------------------- #
# Cross-cutting base-class behaviours (retries / timeouts / rate limits)
# --------------------------------------------------------------------------- #


class TestRetryAndRateLimitBehaviour:
    def test_429_retried_then_succeeds(self, fast_settings) -> None:
        session = FakeSession([
            FakeResponse(429, {}),
            FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 10}}}}),
        ])
        connector = _connector(VirusTotalConnector, "k", session, fast_settings)
        result = connector.enrich(validate_ioc("8.8.8.8"))
        assert result.status is ProviderStatus.OK
        assert len(session.calls) == 2  # one retry happened

    def test_persistent_429_reports_rate_limited(self, fast_settings) -> None:
        session = FakeSession([FakeResponse(429, {})] * fast_settings.max_retries)
        connector = _connector(VirusTotalConnector, "k", session, fast_settings)
        result = connector.enrich(validate_ioc("8.8.8.8"))
        assert result.status is ProviderStatus.RATE_LIMITED
        assert len(session.calls) == fast_settings.max_retries  # bounded, never infinite

    def test_503_retried_then_provider_error(self, fast_settings) -> None:
        session = FakeSession([FakeResponse(503, {})] * fast_settings.max_retries)
        connector = _connector(VirusTotalConnector, "k", session, fast_settings)
        result = connector.enrich(validate_ioc("8.8.8.8"))
        assert result.status is ProviderStatus.PROVIDER_ERROR
        assert len(session.calls) == fast_settings.max_retries

    def test_timeout_maps_to_timeout_status(self, fast_settings) -> None:
        session = FakeSession([requests.exceptions.Timeout()] * fast_settings.max_retries)
        connector = _connector(VirusTotalConnector, "k", session, fast_settings)
        result = connector.enrich(validate_ioc("8.8.8.8"))
        assert result.status is ProviderStatus.TIMEOUT
        # Timeout protection: every attempt passed the configured timeout value.
        assert all(call["timeout"] == fast_settings.timeout_seconds for call in session.calls)

    def test_network_error_maps_to_network_error(self, fast_settings) -> None:
        session = FakeSession([requests.exceptions.ConnectionError()] * fast_settings.max_retries)
        connector = _connector(VirusTotalConnector, "k", session, fast_settings)
        result = connector.enrich(validate_ioc("8.8.8.8"))
        assert result.status is ProviderStatus.NETWORK_ERROR

    def test_transient_failure_then_success_via_retry(self, fast_settings) -> None:
        session = FakeSession([
            requests.exceptions.ConnectionError(),
            FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"harmless": 5}}}}),
        ])
        connector = _connector(VirusTotalConnector, "k", session, fast_settings)
        result = connector.enrich(validate_ioc("8.8.8.8"))
        assert result.status is ProviderStatus.OK
        assert len(session.calls) == 2

    def test_unexpected_exception_never_escapes(self, fast_settings) -> None:
        class Exploding(FakeSession):
            def request(self, *a, **k):  # noqa: D102
                raise RuntimeError("boom - secret internal detail /path?token=abc")

        connector = _connector(VirusTotalConnector, "k", Exploding([]), fast_settings)
        result = connector.enrich(validate_ioc("8.8.8.8"))
        assert result.status is ProviderStatus.PROVIDER_ERROR
        # Error normalisation: raw exception text (may echo URLs) is not leaked.
        assert "boom" not in (result.error or "")

    def test_tls_verification_enabled_by_default(self, fast_settings) -> None:
        connector = VirusTotalConnector("k", fast_settings)  # real requests.Session
        assert connector._session.verify is True
        assert connector._session.headers["User-Agent"].startswith("ioc-intelligence-analyzer/")

    def test_enrichment_result_serialisable(self, fast_settings) -> None:
        session = FakeSession([FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 2}}}})])
        connector = _connector(VirusTotalConnector, "k", session, fast_settings)
        payload = connector.enrich(validate_ioc("8.8.8.8")).to_dict()
        assert payload["provider"] == "virustotal"
        assert isinstance(payload["status"], str)


# --------------------------------------------------------------------------- #
# Connector contract / SOLID checks
# --------------------------------------------------------------------------- #


class TestConnectorContract:
    def test_all_release1_connectors_share_interface(self, fast_settings) -> None:
        for cls in (VirusTotalConnector, AbuseIPDBConnector, GreyNoiseConnector):
            assert issubclass(cls, BaseConnector)
            assert cls.name and cls.display_name
            assert isinstance(cls.supported_types, frozenset)
            assert callable(getattr(cls, "_lookup"))

    def test_ioc_type_matrix(self, fast_settings) -> None:
        vt = VirusTotalConnector("k", fast_settings)
        aidb = AbuseIPDBConnector("k", fast_settings)
        gn = GreyNoiseConnector("k", fast_settings)
        assert IOCType.IPV4 in vt.supported_types
        assert IOCType.SHA256 in vt.supported_types
        assert IOCType.EMAIL not in vt.supported_types
        assert IOCType.DOMAIN not in aidb.supported_types
        assert IOCType.MD5 not in gn.supported_types

    def test_make_ioc_helper_roundtrip(self) -> None:
        ioc = make_ioc("203.0.113.5", IOCType.IPV4, {"is_private": False})
        assert ioc.valid and ioc.metadata["is_private"] is False
