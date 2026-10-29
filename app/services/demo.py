"""Offline demo data generator.

Produces realistic (clearly synthetic) enrichment results so the pipeline and
report renderers can be exercised - and screenshots generated - without API
keys or network access. Never used when live providers return real data.
"""

from __future__ import annotations

from app.core.ioc import validate_ioc
from app.core.models import (
    AnalysisResult,
    BulkAnalysisReport,
    EnrichmentResult,
    ProviderStatus,
)
from app.services.scoring import score_enrichments
from app.services.summary import build_summary


def _demo_vt() -> EnrichmentResult:
    return EnrichmentResult(
        provider="virustotal",
        status=ProviderStatus.OK,
        confidence=68,
        malicious=True,
        summary=(
            "14/72 engines flagged as malicious; 3 suspicious; labels: Trojan.Win32, "
            "Generic.Malware.AI, Heuristic"
        ),
        details={
            "analysis_stats": {"malicious": 14, "suspicious": 3, "harmless": 55},
            "malicious_detectors": ["Trojan.Win32.Generic", "Gen:Variant.Tedy", "Malware.AI"],
            "type": "malicious host",
            "as_owner": "DEMO-NETWORK-64500 (synthetic)",
            "country": "NL",
            "threat_cluster": "demo-cobalt-beacon-cluster",
        },
        raw_ref="https://www.virustotal.com/gui/demo",
    )


def _demo_abuseipdb() -> EnrichmentResult:
    return EnrichmentResult(
        provider="abuseipdb",
        status=ProviderStatus.OK,
        confidence=95,
        malicious=True,
        summary=(
            "Abuse confidence 95% from 214 reports; 41 distinct reporters; categories: "
            "Botnet, SSH, Brute Force"
        ),
        details={
            "abuse_confidence_score": 95,
            "total_reports": 214,
            "distinct_reports": 41,
            "report_categories": ["SSH", "Brute Force", "Botnet"],
            "severe_categories": ["Botnet"],
            "country": "NL",
            "isp": "Demo Hosting B.V.",
            "domain": "demo-hosting.example",
            "last_reported": "2026-10-28T03:11:52Z",
        },
        raw_ref="https://www.abuseipdb.com/check/demo",
    )


def _demo_greynoise() -> EnrichmentResult:
    return EnrichmentResult(
        provider="greynoise",
        status=ProviderStatus.OK,
        confidence=80,
        malicious=True,
        summary="Classification: malicious; Actor: demo-botnet-scanner; Categories: scanner, exploit",
        details={
            "classification": "malicious",
            "actor": "demo-botnet-scanner",
            "categories": ["scanner", "exploit"],
            "organization": "Demo Hosting B.V.",
            "country": "Netherlands",
            "first_seen": "2026-09-14",
            "last_seen": "2026-10-28",
            "noise": False,
        },
        raw_ref="https://www.greynoise.io/viz/address/demo",
    )


def build_demo_result(value: str = "203.0.113.66") -> AnalysisResult:
    """Analyse *value* entirely offline using canned high-risk provider data."""
    ioc = validate_ioc(value)
    if not ioc.valid:
        raise ValueError(f"demo value must itself be a valid IOC: {value}")
    enrichments = [_demo_vt(), _demo_abuseipdb(), _demo_greynoise()]
    risk = score_enrichments(ioc.value, ioc.ioc_type.value, enrichments)
    summary = build_summary(ioc, risk, enrichments)
    return AnalysisResult(ioc=ioc, risk=risk, enrichments=enrichments, summary=summary)


def build_demo_report() -> BulkAnalysisReport:
    """Bulk demo with one critical IP plus one informational domain."""
    critical = build_demo_result("203.0.113.66")

    benign_ioc = validate_ioc("example.org")
    benign_enrichments = [
        EnrichmentResult(
            provider="virustotal",
            status=ProviderStatus.OK,
            confidence=0,
            malicious=False,
            summary="0/72 engines flagged as malicious",
            details={"analysis_stats": {"malicious": 0, "harmless": 72}, "reputation": 0},
        ),
        EnrichmentResult.skipped("abuseipdb", "AbuseIPDB does not support 'domain' indicators"),
        EnrichmentResult.skipped("greynoise", "GreyNoise does not support 'domain' indicators"),
    ]
    benign_risk = score_enrichments(benign_ioc.value, benign_ioc.ioc_type.value, benign_enrichments)
    benign = AnalysisResult(
        ioc=benign_ioc,
        risk=benign_risk,
        enrichments=benign_enrichments,
        summary=build_summary(benign_ioc, benign_risk, benign_enrichments),
    )
    return BulkAnalysisReport(results=[critical, benign])
