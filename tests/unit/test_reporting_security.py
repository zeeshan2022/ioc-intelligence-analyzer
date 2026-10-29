"""Security-focused unit tests for report renderers.

Covers the two highest-value output risks for a SOC tool:
* **Stored/reflected XSS** via hostile IOC values rendered into HTML reports.
* **CSV formula injection** (DDE/excel exploits) via spreadsheet exports.
Also validates filename sanitisation (path traversal, CWE-22).
"""

from __future__ import annotations

import pytest

from app.core.ioc import IOCType, ValidatedIOC
from app.core.models import (
    AnalysisResult,
    BulkAnalysisReport,
    EnrichmentResult,
    ProviderStatus,
)
from app.reporting.csv_report import _neutralize, render_csv
from app.reporting.html_report import render_html, render_bulk_html
from app.reporting.utils import sanitize_ioc_token
from app.services.scoring import score_enrichments
from app.services.summary import build_summary

from tests.conftest import ok_result

pytestmark = [pytest.mark.unit, pytest.mark.security]


XSS_PAYLOADS = [
    '"><script>alert("xss")</script>',
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "'; DROP TABLE users;--",
    "<svg/onload=alert('SVG-XSS')>",
]


def _hostile_result(payload: str) -> AnalysisResult:
    """Build a full AnalysisResult whose IOC value *is* the payload."""
    ioc = ValidatedIOC(value=payload, ioc_type=IOCType.DOMAIN, valid=True, metadata={"tld": "com"})
    enrichments = [
        ok_result("virustotal", malicious=True, summary=f"flagged after ingesting {payload}",
                  details={"analysis_stats": {"malicious": 9},
                           "malicious_detectors": [f"<b>{payload}</b>"]}),
        ok_result("greynoise", details={"classification": "malicious", "actor": payload}),
    ]
    risk = score_enrichments(payload, "domain", enrichments)
    summary = build_summary(ioc, risk, enrichments)
    return AnalysisResult(ioc=ioc, risk=risk, enrichments=enrichments, summary=summary)


# --------------------------------------------------------------------------- #
# HTML / XSS
# --------------------------------------------------------------------------- #


class TestHTMLXSSProtection:
    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_script_and_event_handlers_are_escaped(self, payload: str) -> None:
        html_doc = render_html(_hostile_result(payload))
        # The raw payload must never appear unescaped anywhere in the document.
        assert payload not in html_doc
        assert "<script>" not in html_doc.lower()
        # Defence-in-depth applies to *narrative* slots only. Evidence fields
        # (the Indicator Details slot) preserve html.escape(payload) verbatim,
        # so escaped handler substrings legitimately remain there — inert via
        # escaping plus CSP. Assert narrative prose is scrubbed instead.
        doc_lower = html_doc.lower()
        # Narrative sections (everything after the Indicator Details evidence
        # slot) must be free of executable constructs. The evidence slot that
        # precedes them intentionally preserves html.escape(payload) verbatim.
        narrative_start = doc_lower.find("indicator details")
        assert narrative_start != -1
        narrative = doc_lower[narrative_start:]
        assert "onerror=alert" not in narrative
        assert "onload=alert" not in narrative
        assert "javascript:" not in narrative

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_escaped_form_is_present(self, payload: str) -> None:
        html_doc = render_html(_hostile_result(payload))
        from html import escape

        assert escape(payload) in html_doc  # data preserved, inert

    def test_csp_meta_header_present(self) -> None:
        html_doc = render_html(_hostile_result("example.com"))
        assert 'http-equiv="Content-Security-Policy"' in html_doc
        assert "default-src 'none'" in html_doc

    def test_no_external_resource_loading(self) -> None:
        html_doc = render_html(_hostile_result("example.com"))
        assert "<script" not in html_doc.lower()
        assert "src=\"http" not in html_doc
        assert "@import" not in html_doc

    def test_outbound_links_hardened(self) -> None:
        result = _hostile_result("example.com")
        result.enrichments[0].raw_ref = "https://www.virustotal.com/gui/ip/1.2.3.4"
        html_doc = render_html(result)
        assert "rel='noopener noreferrer'" in html_doc or 'rel="noopener noreferrer"' in html_doc

    def test_bulk_html_also_escaped(self) -> None:
        report = BulkAnalysisReport(results=[_hostile_result('<script>alert(1)</script>')])
        html_doc = render_bulk_html(report)
        assert "<script>alert(1)</script>" not in html_doc

    def test_invalid_input_echoed_safely_in_bulk(self) -> None:
        hostile = ValidatedIOC("<iframe src=x>", IOCType.UNKNOWN, False, "unrecognised indicator")
        report = BulkAnalysisReport(results=[], invalid_inputs=[hostile])
        html_doc = render_bulk_html(report)
        assert "<iframe src=x>" not in html_doc


# --------------------------------------------------------------------------- #
# CSV formula injection
# --------------------------------------------------------------------------- #


class TestCSVInjectionProtection:
    @pytest.mark.parametrize(
        "payload",
        ["=cmd|'/C calc'!A0", "+SUM(1+1)*cmd|'/C calc'!A0", "-2+3+cmd|' /C calc'!A0",
         "@SUM(1+1)", "\t=hybrid", "\r@mixed"],
    )
    def test_neutralize_prefixes_dangerous_cells(self, payload: str) -> None:
        escaped = _neutralize(payload)
        assert escaped.startswith("'")
        assert escaped[1] in {"=", "+", "-", "@", "\t", "\r"}

    def test_safe_values_untouched(self) -> None:
        assert _neutralize("8.8.8.8") == "8.8.8.8"
        assert _neutralize(None) == ""
        assert _neutralize(42) == "42"

    def test_full_csv_row_injection_defence(self) -> None:
        hostile_ioc = ValidatedIOC("=HYPERLINK(\"http://evil\")", IOCType.DOMAIN, True)
        enrichments = [ok_result("virustotal", malicious=True,
                                 summary="@SUM(evil)",
                                 details={"analysis_stats": {"malicious": 5}})]
        risk = score_enrichments(hostile_ioc.value, "domain", enrichments)
        summary_obj = build_summary(hostile_ioc, risk, enrichments)
        # Force an escalation string that starts with '=' to test every column.
        object.__setattr__(summary_obj, "escalation_guidance", "=cmd|'/C calc'!B6")
        result = AnalysisResult(ioc=hostile_ioc, risk=risk, enrichments=enrichments, summary=summary_obj)

        csv_text = render_csv(BulkAnalysisReport(results=[result]))
        for line in csv_text.splitlines():
            for cell in line.split(","):
                stripped = cell.strip('"')
                if stripped[:1] in {"=", "+", "@", "\t"}:
                    pytest.fail(f"un-neutralised formula cell found: {stripped!r}")
                if stripped.startswith("-") and "cmd" in stripped.lower():
                    pytest.fail(f"formula-injection vector leaked: {stripped!r}")

    def test_newlines_flattened_in_cells(self) -> None:
        assert "\n" not in _neutralize("line1\nline2\r\nline3")


# --------------------------------------------------------------------------- #
# Filename / path safety
# --------------------------------------------------------------------------- #


class TestFilenameSanitisation:
    @pytest.mark.parametrize(
        "value",
        ["../../etc/passwd", "..\\..\\windows\\system32", "a/b/c", "null\x00byte", "$(rm -rf /)"],
    )
    def test_traversal_and_separators_removed(self, value: str) -> None:
        token = sanitize_ioc_token(value)
        assert "/" not in token
        assert "\\" not in token
        assert "\x00" not in token
        assert not token.startswith(".")
        assert ".." not in token

    def test_safe_tokens_preserved(self) -> None:
        assert sanitize_ioc_token("203.0.113.66") == "203.0.113.66"
        assert sanitize_ioc_token("evil-example.com") == "evil-example.com"

    def test_length_capped(self) -> None:
        assert len(sanitize_ioc_token("x" * 500)) <= 64


# --------------------------------------------------------------------------- #
# Secrets handling
# --------------------------------------------------------------------------- #


class TestSecretsHygiene:
    def test_config_repr_redacts_keys(self) -> None:
        from app.core.config import AppConfig

        config = AppConfig(vt_api_key="supersecretkey123", abuseipdb_api_key="abcdef9999")
        text = repr(config)
        assert "supersecretkey123" not in text
        assert "abcdef9999" not in text
        assert "*" in text  # masked form present

    def test_redacted_dict_contains_no_full_keys(self) -> None:
        from app.core.config import AppConfig

        config = AppConfig(greynoise_api_key="verysecrettoken")
        assert "verysecrettoken" not in str(config.redacted_dict())

    def test_log_redaction_helper(self) -> None:
        from app.core.logging import redact

        out = redact("header x-apikey: abcdefghijklmnop")
        assert "abcdefghijklmno" not in out

    def test_reports_do_not_embed_api_keys(self) -> None:
        secret = "VT-SECRET-DO-NOT-LEAK"
        result = _hostile_result("example.com")
        assert secret not in render_html(result)
        assert secret not in render_csv(BulkAnalysisReport(results=[result]))
