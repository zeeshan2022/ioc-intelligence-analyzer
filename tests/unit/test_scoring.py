"""Unit tests for the explainable risk-scoring engine."""

from __future__ import annotations

import pytest

from app.core.models import RiskLevel, score_to_level
from app.services.scoring import score_enrichments

from tests.conftest import ok_result

pytestmark = pytest.mark.unit


def _score(results, value="203.0.113.66", ioc_type="ipv4"):
    return score_enrichments(value, ioc_type, results)


# --------------------------------------------------------------------------- #
# Band mapping
# --------------------------------------------------------------------------- #


class TestRiskBands:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0, RiskLevel.INFORMATIONAL),
            (20, RiskLevel.INFORMATIONAL),
            (21, RiskLevel.LOW),
            (40, RiskLevel.LOW),
            (41, RiskLevel.MEDIUM),
            (60, RiskLevel.MEDIUM),
            (61, RiskLevel.HIGH),
            (80, RiskLevel.HIGH),
            (81, RiskLevel.CRITICAL),
            (100, RiskLevel.CRITICAL),
        ],
    )
    def test_band_boundaries(self, score: int, expected: RiskLevel) -> None:
        assert score_to_level(score) is expected

    def test_clamping(self) -> None:
        assert score_to_level(-5) is RiskLevel.INFORMATIONAL
        assert score_to_level(250) is RiskLevel.CRITICAL


# --------------------------------------------------------------------------- #
# Documented rubric signals
# --------------------------------------------------------------------------- #


class TestRubricSignals:
    def test_no_results_is_informational(self) -> None:
        assessment = _score([])
        assert assessment.score == 0
        assert assessment.level is RiskLevel.INFORMATIONAL
        assert assessment.explanation

    def test_virustotal_malicious_awards_up_to_30(self) -> None:
        vt = ok_result(
            "virustotal",
            confidence=70,
            malicious=True,
            summary="14/72 engines flagged as malicious",
            details={"analysis_stats": {"malicious": 14, "suspicious": 3, "harmless": 55}},
        )
        assessment = _score([vt])
        names = {f.name for f in assessment.factors}
        assert "VirusTotal detections" in names
        points = {f.name: f.points for f in assessment.factors}["VirusTotal detections"]
        assert points == 30

    def test_single_vt_detection_scaled_down(self) -> None:
        vt = ok_result(
            "virustotal",
            malicious=True,
            details={"analysis_stats": {"malicious": 1, "harmless": 70}},
        )
        points = {f.name: f.points for f in _score([vt]).factors}
        assert points.get("VirusTotal detections") == 18  # 15 + 3*1

    def test_abuseipdb_high_confidence_awards_25(self) -> None:
        aidb = ok_result(
            "abuseipdb",
            confidence=95,
            malicious=True,
            summary="Abuse confidence 95%",
            details={"abuse_confidence_score": 95, "total_reports": 42},
        )
        points = {f.name: f.points for f in _score([aidb]).factors}
        assert points.get("AbuseIPDB abuse confidence") == 25

    def test_abuseipdb_moderate_confidence_awards_15(self) -> None:
        aidb = ok_result(
            "abuseipdb",
            confidence=30,
            details={"abuse_confidence_score": 30, "total_reports": 3},
        )
        points = {f.name: f.points for f in _score([aidb]).factors}
        assert points.get("AbuseIPDB moderate confidence") == 15

    def test_whitelist_is_mitigating(self) -> None:
        aidb = ok_result(
            "abuseipdb",
            confidence=0,
            malicious=False,
            details={"abuse_confidence_score": 0, "total_reports": 0, "is_whitelisted": True},
        )
        factors = {f.name: f.points for f in _score([aidb]).factors}
        assert factors.get("AbuseIPDB whitelist") == -10

    def test_botnet_signal_awards_20(self) -> None:
        aidb = ok_result(
            "abuseipdb",
            details={"severe_categories": ["Botnet"], "abuse_confidence_score": 10, "total_reports": 1},
        )
        points = {f.name: f.points for f in _score([aidb]).factors}
        assert points.get("Known botnet infrastructure") == 20

    def test_malware_hosting_awards_15(self) -> None:
        vt = ok_result("virustotal", summary="hosts Emotet trojan downloader samples")
        points = {f.name: f.points for f in _score([vt]).factors}
        assert points.get("Malware hosting / delivery") == 15

    def test_greynoise_malicious_awards_20_benign_subtracts_10(self) -> None:
        malicious = ok_result("greynoise", details={"classification": "malicious", "actor": "mirai-scanner"})
        benign = ok_result("greynoise", details={"classification": "benign"})
        assert {f.name: f.points for f in _score([malicious]).factors}.get(
            "GreyNoise malicious classification"
        ) == 20
        assert {f.name: f.points for f in _score([benign]).factors}.get(
            "GreyNoise benign background noise"
        ) == -10

    def test_corroboration_bonus_with_two_malicious_votes(self) -> None:
        vt = ok_result("virustotal", malicious=True,
                       details={"analysis_stats": {"malicious": 10}})
        gn = ok_result("greynoise", malicious=True, details={"classification": "malicious"})
        points = {f.name: f.points for f in _score([vt, gn]).factors}
        assert points.get("Multi-provider corroboration") == 10

    def test_provider_failures_never_add_points(self) -> None:
        from app.core.models import EnrichmentResult, ProviderStatus

        failed = EnrichmentResult.failure("virustotal", ProviderStatus.TIMEOUT, "Request timed out")
        assessment = _score([failed])
        assert assessment.score == 0
        assert assessment.factors == []


# --------------------------------------------------------------------------- #
# End-to-end band outcomes + explanation quality
# --------------------------------------------------------------------------- #


class TestScoreOutcomes:
    def build_critical(self):
        vt = ok_result(
            "virustotal", confidence=80, malicious=True,
            summary="20/72 engines malicious; labels: botnet, trojan",
            details={"analysis_stats": {"malicious": 20}, "severe_categories": ["Botnet"]},
        )
        aidb = ok_result(
            "abuseipdb", confidence=100, malicious=True,
            details={"abuse_confidence_score": 100, "total_reports": 500,
                     "severe_categories": ["Botnet", "Malicious Host"]},
        )
        gn = ok_result("greynoise", malicious=True, details={"classification": "malicious"})
        return [vt, aidb, gn]

    def test_all_signals_clamp_to_critical_100(self) -> None:
        assessment = _score(self.build_critical())
        assert assessment.score == 100
        assert assessment.level is RiskLevel.CRITICAL

    def test_medium_band_from_partial_intel(self) -> None:
        vt = ok_result("virustotal", malicious=True,
                       details={"analysis_stats": {"malicious": 5}})
        aidb = ok_result("abuseipdb", details={"abuse_confidence_score": 30, "total_reports": 2})
        assessment = _score([vt, aidb])
        assert assessment.level is RiskLevel.MEDIUM

    def test_low_band_single_weak_signal(self) -> None:
        vt = ok_result("virustotal", details={"analysis_stats": {"suspicious": 3, "harmless": 60}})
        assessment = _score([vt])
        assert 21 <= assessment.score <= 40 or assessment.level is RiskLevel.LOW

    def test_explanation_mentions_indicator_and_level(self) -> None:
        assessment = _score(self.build_critical(), value="198.51.100.7")
        assert "198.51.100.7" in assessment.explanation
        assert assessment.level.value.upper() in assessment.explanation.upper()

    def test_every_factor_carries_evidence(self) -> None:
        for factor in _score(self.build_critical()).factors:
            assert factor.points != 0
            assert len(factor.explanation) > 10

    def test_score_equals_clamped_sum_of_factors(self) -> None:
        assessment = _score(self.build_critical())
        raw = sum(f.points for f in assessment.factors)
        assert assessment.score == max(0, min(100, raw))
