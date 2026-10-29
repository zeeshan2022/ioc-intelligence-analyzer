"""Domain models shared by connectors, the scoring engine and reporters.

All models are plain dataclasses with explicit ``to_dict`` serializers so that
JSON/HTML/Markdown/CSV rendering never depends on a web framework (clean
architecture: domain has no infrastructure dependencies).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from app.core.ioc import ValidatedIOC


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Provider / enrichment models
# --------------------------------------------------------------------------- #


class ProviderStatus(str, Enum):
    """Normalised outcome of a connector invocation."""

    OK = "ok"                    # Successful lookup with usable data
    NO_DATA = "no_data"          # Provider reachable, indicator unknown to it
    SKIPPED = "skipped"          # Connector not applicable for this IOC type
    CONFIGURATION_ERROR = "configuration_error"  # Missing API key etc.
    RATE_LIMITED = "rate_limited"
    AUTHENTICATION_ERROR = "authentication_error"
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    PROVIDER_ERROR = "provider_error"
    PARSE_ERROR = "parse_error"

    @property
    def is_failure(self) -> bool:
        return self not in {ProviderStatus.OK, ProviderStatus.NO_DATA, ProviderStatus.SKIPPED}


@dataclass
class EnrichmentResult:
    """One normalised finding returned by a threat-intelligence provider.

    Attributes:
        provider: Provider identifier, e.g. ``virustotal``.
        status: Normalised :class:`ProviderStatus`.
        confidence: 0-100 analyst confidence in the malicious signal
            (provider-native metric where available).
        malicious: Tri-state verdict (``True``/``False``/``None`` unknown).
        summary: One-line human readable finding.
        details: Provider-specific structured payload (already trimmed).
        error: Human-safe error description; never contains secrets.
        raw_ref: Optional URL to the provider's own report page.
    """

    provider: str
    status: ProviderStatus = ProviderStatus.OK
    confidence: int = 0
    malicious: Optional[bool] = None
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    raw_ref: Optional[str] = None
    retrieved_at: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status.value,
            "confidence": self.confidence,
            "malicious": self.malicious,
            "summary": self.summary,
            "details": self.details,
            "error": self.error,
            "raw_ref": self.raw_ref,
            "retrieved_at": self.retrieved_at,
        }

    @classmethod
    def skipped(cls, provider: str, reason: str) -> "EnrichmentResult":
        return cls(
            provider=provider,
            status=ProviderStatus.SKIPPED,
            summary=reason,
        )

    @classmethod
    def failure(cls, provider: str, status: ProviderStatus, error: str) -> "EnrichmentResult":
        return cls(provider=provider, status=status, error=error, summary=error)


# --------------------------------------------------------------------------- #
# Risk model
# --------------------------------------------------------------------------- #


class RiskLevel(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Score band boundaries (inclusive lower bound), per the documented rubric.
RISK_BANDS: tuple[tuple[int, RiskLevel], ...] = (
    (81, RiskLevel.CRITICAL),
    (61, RiskLevel.HIGH),
    (41, RiskLevel.MEDIUM),
    (21, RiskLevel.LOW),
    (0, RiskLevel.INFORMATIONAL),
)


def score_to_level(score: int) -> RiskLevel:
    """Map a 0-100 risk score onto its qualitative band."""
    clamped = max(0, min(100, int(score)))
    for lower, level in RISK_BANDS:
        if clamped >= lower:
            return level
    return RiskLevel.INFORMATIONAL  # pragma: no cover - bands cover 0..100


@dataclass
class ScoreFactor:
    """A single additive contribution to the final risk score."""

    name: str
    points: int
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "points": self.points, "explanation": self.explanation}


@dataclass
class RiskAssessment:
    """Output of the deterministic risk-scoring engine."""

    score: int
    level: RiskLevel
    factors: list[ScoreFactor] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level.value,
            "factors": [f.to_dict() for f in self.factors],
            "explanation": self.explanation,
        }


# --------------------------------------------------------------------------- #
# Analyst narrative
# --------------------------------------------------------------------------- #


@dataclass
class MitreTechnique:
    """MITRE ATT&CK mapping entry produced by the enrichment mapper."""

    tactic: str
    technique_id: str
    technique_name: str
    rationale: str

    def to_dict(self) -> dict[str, str]:
        return {
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "rationale": self.rationale,
        }


@dataclass
class AnalystSummary:
    """Structured narrative sections rendered into every report format."""

    executive_summary: str
    threat_assessment: str
    observed_activity: list[str]
    risk_rating: str
    mitre_techniques: list[MitreTechnique]
    recommended_actions: list[str]
    containment_recommendations: list[str]
    escalation_guidance: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "executive_summary": self.executive_summary,
            "threat_assessment": self.threat_assessment,
            "observed_activity": self.observed_activity,
            "risk_rating": self.risk_rating,
            "mitre_techniques": [m.to_dict() for m in self.mitre_techniques],
            "recommended_actions": self.recommended_actions,
            "containment_recommendations": self.containment_recommendations,
            "escalation_guidance": self.escalation_guidance,
        }


# --------------------------------------------------------------------------- #
# Aggregate result
# --------------------------------------------------------------------------- #


@dataclass
class AnalysisResult:
    """Complete outcome of analysing one IOC end-to-end."""

    ioc: ValidatedIOC
    risk: RiskAssessment
    enrichments: list[EnrichmentResult]
    summary: AnalystSummary
    analysis_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: str = field(default_factory=_utcnow_iso)
    tool_version: str = "1.0.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
            "ioc": self.ioc.to_dict(),
            "risk": self.risk.to_dict(),
            "enrichments": [e.to_dict() for e in self.enrichments],
            "analyst_summary": self.summary.to_dict(),
        }


@dataclass
class BulkAnalysisReport:
    """Container for multi-IOC runs (CLI ``--bulk`` and later API bulk endpoint)."""

    results: list[AnalysisResult] = field(default_factory=list)
    invalid_inputs: list[ValidatedIOC] = field(default_factory=list)
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "counts": {
                "analysed": len(self.results),
                "invalid": len(self.invalid_inputs),
            },
            "results": [r.to_dict() for r in self.results],
            "invalid_inputs": [i.to_dict() for i in self.invalid_inputs],
        }
