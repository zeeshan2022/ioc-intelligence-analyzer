"""Unit tests for MITRE ATT&CK mapping and the analyst summary generator."""

from __future__ import annotations

import pytest

from app.core.ioc import validate_ioc
from app.core.models import RiskLevel
from app.services.mitre import map_techniques
from app.services.summary import build_summary

from tests.conftest import ok_result

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------- #
# MITRE mapping
# --------------------------------------------------------------------------- #


class TestMitreMapping:
    def test_c2_signals_map_to_command_and_control(self) -> None:
        results = [ok_result("virustotal", summary="Cobalt Strike beacon detected",
                             details={"malicious_detectors": ["Trojan.CobaltStrike.Beacon"]})]
        techniques = map_techniques(results)
        ids = {t.technique_id for t in techniques}
        assert any(tid.startswith("T1") for tid in ids)
        tactics = {t.tactic for t in techniques}
        assert "Command and Control" in tactics or "Command And Control" in tactics

    def test_botnet_scanner_maps_to_recon_or_persistence(self) -> None:
        results = [ok_result("greynoise", details={"classification": "malicious", "actor": "mirai-botnet"})]
        techniques = map_techniques(results)
        assert techniques
        for tech in techniques:
            assert tech.technique_id and tech.technique_name and tech.rationale

    def test_no_evidence_yields_no_mapping(self) -> None:
        assert map_techniques([]) == []
        assert map_techniques([ok_result("virustotal", summary="0/72 engines flagged as malicious")]) == []

    def test_phishing_email_maps_to_initial_access(self) -> None:
        results = [ok_result("virustotal", summary="spearphishing attachment dropper")]
        techniques = map_techniques(results)
        ids = {t.technique_id for t in techniques}
        assert "T1566" in ids  # Phishing - Initial Access

    def test_exfiltration_keyword_mapped(self) -> None:
        results = [ok_result("virustotal", summary="hosts exfil uploader stealer panel")]
        ids = {t.technique_id for t in map_techniques(results)}
        assert "T1567" in ids or "T1041" in ids

    def test_credentials_bruteforce_mapped(self) -> None:
        results = [ok_result("abuseipdb", summary="SSH brute force credential access attempts")]
        ids = {t.technique_id for t in map_techniques(results)}
        assert "T1110" in ids

    def test_mapping_deduplicated(self) -> None:
        dup = ok_result("virustotal", summary="cobalt strike beacon c2")
        dup2 = ok_result("greynoise", summary="cobalt strike beacon c2")
        ids = [t.technique_id for t in map_techniques([dup, dup2])]
        assert len(ids) == len(set(ids))


# --------------------------------------------------------------------------- #
# Analyst summary sections
# --------------------------------------------------------------------------- #


def _summary_for(level_results, value="203.0.113.66"):
    from app.services.scoring import score_enrichments

    ioc = validate_ioc(value)
    risk = score_enrichments(ioc.value, ioc.ioc_type.value, level_results)
    return build_summary(ioc, risk, level_results), risk


class TestAnalystSummary:
    def test_all_required_sections_present(self) -> None:
        results = [
            ok_result("virustotal", confidence=80, malicious=True,
                      summary="20/72 engines malicious; trojan botnet C2",
                      details={"analysis_stats": {"malicious": 20}, "severe_categories": ["Botnet"]}),
            ok_result("abuseipdb", confidence=100, malicious=True,
                      summary="Abuse confidence 100%",
                      details={"abuse_confidence_score": 100, "total_reports": 999}),
            ok_result("greynoise", malicious=True,
                      details={"classification": "malicious", "actor": "mozi"}),
        ]
        summary, risk = _summary_for(results)
        assert risk.level is RiskLevel.CRITICAL
        assert summary.executive_summary.strip()
        assert summary.threat_assessment.strip()
        assert summary.observed_activity
        assert "CRITICAL" in summary.risk_rating
        assert summary.mitre_techniques
        assert summary.recommended_actions
        assert summary.containment_recommendations
        assert summary.escalation_guidance.strip()
        payload = summary.to_dict()
        assert set(payload) == {
            "executive_summary", "threat_assessment", "observed_activity", "risk_rating",
            "mitre_techniques", "recommended_actions", "containment_recommendations",
            "escalation_guidance",
        }

    def test_informational_run_still_produces_guidance(self) -> None:
        clean = ok_result("virustotal", malicious=False,
                          summary="0/72 engines flagged as malicious",
                          details={"analysis_stats": {"malicious": 0, "harmless": 72}})
        summary, risk = _summary_for([clean], value="example.org")
        assert risk.score <= 20
        assert summary.recommended_actions  # never empty - analysts always get next steps
        assert summary.escalation_guidance

    def test_executive_summary_names_indicator(self) -> None:
        benign = ok_result("virustotal", malicious=False, details={"analysis_stats": {"harmless": 10}})
        summary, _ = _summary_for([benign], value="example.org")
        assert "example.org" in summary.executive_summary

    def test_provider_outage_flagged_in_escalation(self) -> None:
        from app.core.models import EnrichmentResult, ProviderStatus

        failed = EnrichmentResult.failure("virustotal", ProviderStatus.RATE_LIMITED, "rate limited")
        ioc = validate_ioc("203.0.113.66")
        from app.services.scoring import score_enrichments

        risk = score_enrichments(ioc.value, "ipv4", [failed])
        summary = build_summary(ioc, risk, [failed])
        assert summary.escalation_guidance  # outage must still yield guidance text

    def test_observed_activity_quotes_provider_findings(self) -> None:
        vt = ok_result("virustotal", malicious=True,
                       summary="14/72 engines flagged as malicious",
                       details={"analysis_stats": {"malicious": 14}})
        summary, _ = _summary_for([vt])
        joined = " ".join(summary.observed_activity)
        assert "virustotal" in joined.lower() or "14/72" in joined

    def test_high_risk_contains_block_containment(self) -> None:
        results = [
            ok_result("virustotal", malicious=True,
                      summary="ransomware staging server",
                      details={"analysis_stats": {"malicious": 30}}),
            ok_result("abuseipdb", malicious=True,
                      details={"abuse_confidence_score": 90, "total_reports": 50}),
        ]
        summary, risk = _summary_for(results)
        assert risk.score >= 61
        text = " ".join(summary.containment_recommendations).lower()
        assert any(word in text for word in ("block", "quarantine", "blacklist", "deny"))
