"""Integration tests: full pipeline with mocked HTTP transport.

These exercise validate -> enrich -> score -> MITRE -> summarise -> render for
every output format, plus the privacy control that keeps internal addresses
off the wire. No real network calls are made (enforced by conftest).
"""

from __future__ import annotations

import json

import pytest

from app.connectors.abuseipdb import AbuseIPDBConnector
from app.connectors.greynoise import GreyNoiseConnector
from app.connectors.virustotal import VirusTotalConnector
from app.core.config import AppConfig, ConnectorSettings
from app.core.models import ProviderStatus
from app.reporting.csv_report import render_csv, render_provider_detail_csv
from app.reporting.html_report import render_bulk_html, render_html
from app.reporting.json_report import render_bulk_json, render_json
from app.reporting.markdown_report import render_bulk_markdown, render_markdown
from app.services.analyzer import IOCAnalyzer, read_indicator_file
from app.services.demo import build_demo_report, build_demo_result

from tests.conftest import FakeResponse, FakeSession

pytestmark = [pytest.mark.integration]

VT_MALICIOUS = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 15, "suspicious": 2, "harmless": 55},
            "last_analysis_results": {
                "K7AntiVirus": {"category": "malicious", "result": "Trojan.Win32.Cobalt"}
            },
            "country": "RU",
            "as_owner": "Evil Hosting LLC",
        },
        "links": {"self": "https://www.virustotal.com/api/v3/ip_addresses/203.0.113.66"},
    }
}
AIDB_HIGH = {
    "data": {
        "abuseConfidenceScore": 98,
        "totalReports": 240,
        "numDistinctReports": 87,
        "blacklistCategories": [{"id": 8, "name": "Botnet"}],
        "countryCode": "RU",
        "isp": "Evil Hosting LLC",
        "isWhitelisted": False,
        "lastReportedAt": "2026-10-27T08:00:00+00:00",
    }
}
GN_MALICIOUS = {
    "classification": "malicious",
    "actor": "qakbot-botnet",
    "categories": ["botnet"],
    "org": "Evil Hosting LLC",
    "country_name": "RU",
    "seen_last": "2026-10-28T23:00:00Z",
}


def _malicious_analyzer(tmp_path) -> IOCAnalyzer:
    settings = ConnectorSettings(timeout_seconds=1.0, max_retries=2, backoff_factor=0.0)
    vt = VirusTotalConnector("vt-key", settings, session=FakeSession([FakeResponse(200, VT_MALICIOUS)]))
    aidb = AbuseIPDBConnector("aidb-key", settings, session=FakeSession([FakeResponse(200, AIDB_HIGH)]))
    gn = GreyNoiseConnector("gn-key", settings, session=FakeSession([FakeResponse(200, GN_MALICIOUS)]))
    config = AppConfig(report_output_dir=tmp_path / "reports")
    return IOCAnalyzer(config, connectors=[vt, aidb, gn])


class TestEndToEndPipeline:
    def test_malicious_ip_full_pipeline(self, tmp_path) -> None:
        analyzer = _malicious_analyzer(tmp_path)
        result = analyzer.analyze("203.0.113.66")

        assert result is not None
        assert result.risk.score >= 81
        assert result.risk.level.value == "critical"
        assert {e.provider for e in result.enrichments} == {"virustotal", "abuseipdb", "greynoise"}
        assert all(e.status is ProviderStatus.OK for e in result.enrichments)
        assert result.summary.mitre_techniques
        assert result.summary.executive_summary

    def test_all_formats_render_from_same_result(self, tmp_path) -> None:
        analyzer = _malicious_analyzer(tmp_path)
        result = analyzer.analyze("203.0.113.66")
        assert result is not None

        payload = json.loads(render_json(result))
        assert payload["risk"]["score"] == result.risk.score
        assert payload["ioc"]["value"] == "203.0.113.66"

        html_doc = render_html(result)
        assert html_doc.startswith("<!DOCTYPE html>")
        assert "MITRE ATT&amp;CK Mapping" in html_doc
        assert "Critical".upper() in html_doc.upper()

        markdown = render_markdown(result)
        assert markdown.startswith("# IOC Intelligence Report")
        assert "## Executive Summary" in markdown or "Executive Summary" in markdown

        csv_text = render_csv(result)  # accepts single AnalysisResult (wrapped internally)
        assert "risk_score" in csv_text.splitlines()[0]
        from app.core.models import BulkAnalysisReport

        detail = render_provider_detail_csv(BulkAnalysisReport(results=[result]))
        assert "virustotal" in detail

    def test_private_ip_never_leaves_the_building(self, tmp_path) -> None:
        """Privacy control: RFC1918 addresses must not hit provider sessions."""
        vt_session = FakeSession([])  # any call would raise AssertionError
        settings = ConnectorSettings(timeout_seconds=1.0, max_retries=1, backoff_factor=0.0)
        analyzer = IOCAnalyzer(
            AppConfig(report_output_dir=tmp_path),
            connectors=[
                VirusTotalConnector("vt-key", settings, session=vt_session),
                AbuseIPDBConnector("k", settings, session=FakeSession([])),
                GreyNoiseConnector("k", settings, session=FakeSession([])),
            ],
        )
        result = analyzer.analyze("192.168.1.10")
        assert result is not None
        assert vt_session.calls == []  # zero outbound requests
        assert all(e.status is ProviderStatus.SKIPPED for e in result.enrichments)
        assert "private/reserved" in result.enrichments[0].summary.lower()

    def test_reserved_and_loopback_also_blocked(self, tmp_path) -> None:
        settings = ConnectorSettings(timeout_seconds=1.0, max_retries=1, backoff_factor=0.0)
        session = FakeSession([])
        analyzer = IOCAnalyzer(
            AppConfig(report_output_dir=tmp_path),
            connectors=[VirusTotalConnector("k", settings, session=session)],
        )
        for internal in ("10.0.0.5", "127.0.0.1", "169.254.169.254", "240.0.0.1"):
            analyzer.analyze(internal)
        assert session.calls == []

    def test_offline_mode_skips_everything(self, tmp_path) -> None:
        settings = ConnectorSettings(timeout_seconds=1.0, max_retries=1, backoff_factor=0.0)
        session = FakeSession([])
        analyzer = IOCAnalyzer(
            AppConfig(offline_mode=True, report_output_dir=tmp_path),
            connectors=[VirusTotalConnector("k", settings, session=session)],
        )
        result = analyzer.analyze("8.8.8.8")
        assert result is not None
        assert session.calls == []
        assert all(e.status is ProviderStatus.SKIPPED for e in result.enrichments)

    def test_unconfigured_keys_degrade_gracefully(self, tmp_path) -> None:
        analyzer = IOCAnalyzer(AppConfig(report_output_dir=tmp_path))  # default connectors, no keys
        result = analyzer.analyze("203.0.113.66")
        assert result is not None
        assert all(e.status is ProviderStatus.CONFIGURATION_ERROR for e in result.enrichments)
        assert result.risk.score == 0  # missing intel must never inflate risk

    def test_invalid_input_returns_none(self, tmp_path) -> None:
        analyzer = IOCAnalyzer(AppConfig(report_output_dir=tmp_path))
        assert analyzer.analyze("not a valid ioc!!") is None

    def test_bulk_run_partitions_valid_invalid(self, tmp_path) -> None:
        analyzer = _malicious_analyzer(tmp_path)
        report = analyzer.analyze_bulk(["203.0.113.66", "garbage!!", "", "203.0.113.66"])
        assert len(report.results) == 1  # deduped
        assert len(report.invalid_inputs) == 2
        bulk_json = json.loads(render_bulk_json(report))
        assert bulk_json["counts"] == {"analysed": 1, "invalid": 2}


class TestFileIngestion:
    def test_read_plain_line_file_with_comments(self, tmp_path) -> None:
        f = tmp_path / "indicators.txt"
        f.write_text("# threat feed export\n8.8.8.8\n\nexample.com\n", encoding="utf-8")
        values = read_indicator_file(f)
        assert values == ["8.8.8.8", "example.com"]

    def test_read_csv_first_column(self, tmp_path) -> None:
        f = tmp_path / "indicators.csv"
        f.write_text("ioc,notes\n8.8.8.8,dns resolver\nexample.com,c2 domain\n", encoding="utf-8")
        values = read_indicator_file(f)
        assert values == ["8.8.8.8", "example.com"]

    def test_read_json_array(self, tmp_path) -> None:
        f = tmp_path / "feed.json"
        f.write_text('["8.8.8.8", "example.com"]', encoding="utf-8")
        assert read_indicator_file(f) == ["8.8.8.8", "example.com"]

    def test_missing_file_raises(self, tmp_path) -> None:
        with pytest.raises(FileNotFoundError):
            read_indicator_file(tmp_path / "nope.csv")

    def test_analyze_file_end_to_end(self, tmp_path) -> None:
        f = tmp_path / "bulk.csv"
        f.write_text("ioc\n203.0.113.66\nbogus!!!\n", encoding="utf-8")
        analyzer = _malicious_analyzer(tmp_path)
        report = analyzer.analyze_file(f)
        assert len(report.results) == 1
        assert len(report.invalid_inputs) == 1
        html_doc = render_bulk_html(report)
        assert "203.0.113.66" in html_doc
        md = render_bulk_markdown(report)
        assert "bogus" in md  # rejected inputs surfaced for triage feedback


class TestDemoMode:
    def test_demo_result_is_deterministic_and_critical(self) -> None:
        first = build_demo_result()
        second = build_demo_result()
        assert first.risk.score == second.risk.score == 100
        assert first.risk.level.value == "critical"

    def test_demo_report_has_two_iocs(self) -> None:
        report = build_demo_report()
        assert len(report.results) == 2
        scores = sorted(r.risk.score for r in report.results)
        assert scores == [0, 100]

    def test_demo_renders_all_formats(self) -> None:
        report = build_demo_report()
        assert render_bulk_json(report)
        assert render_bulk_html(report)
        assert render_bulk_markdown(report)
        for result in report.results:
            assert render_html(result)
            assert render_csv(result)
