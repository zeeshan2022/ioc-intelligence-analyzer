"""Analyst summary generator.

Turns (validated IOC + risk assessment + enrichments + ATT&CK mappings) into
the structured narrative sections required by SOC reporting standards:
executive summary, threat assessment, observed activity, risk rating, MITRE
mapping, recommended/containment actions and escalation guidance.

Release 1 uses deterministic templating with evidence interpolation; Release 3
will swap the prose generator for an AI-assisted writer behind this same
``build_summary`` interface.
"""

from __future__ import annotations

import re

from app.core.ioc import ValidatedIOC
from app.core.models import (
    AnalystSummary,
    EnrichmentResult,
    MitreTechnique,
    RiskAssessment,
    RiskLevel,
)
def _narrate(value: object) -> str:
    """Return an IOC value safe for embedding in *narrative* prose.

    Narrative sentences interpolate the indicator string; a hostile payload
    must not smuggle markup or event-handler substrings into analyst prose, so
    injection characters are stripped here. Evidence fields in renderers keep
    the verbatim value via ``html.escape(payload)`` — this helper never
    touches those slots.
    """
    text = "" if value is None else str(value)
    for ch in "<>\"'&`":
        text = text.replace(ch, "")
    # Narrative prose must never carry executable constructs, even quoted.
    text = re.sub(r"(?i)\bon[a-z]+=", "handler-neutralized=", text)
    text = re.sub(r"(?i)javascript\s*:", "protocol-neutralized:", text)
    return text


from app.services.mitre import map_techniques


def build_summary(
    ioc: ValidatedIOC,
    risk: RiskAssessment,
    enrichments: list[EnrichmentResult],
    mitre: list[MitreTechnique] | None = None,
) -> AnalystSummary:
    """Compose the full analyst narrative for one analysed indicator."""
    mitre = mitre if mitre is not None else map_techniques(enrichments)

    usable = [e for e in enrichments if e.status.value == "ok"]
    failures = [e for e in enrichments if e.status.is_failure]
    skipped = [e for e in enrichments if e.status.value == "skipped"]

    providers = ", ".join(sorted({e.provider for e in usable})) or "none returned data"
    level = risk.level

    executive = _executive(ioc, risk, level, len(usable))
    threat = _threat_assessment(level, usable)
    observed = _observed_activity(usable)
    actions = _recommended_actions(level, ioc)
    containment = _containment(level, ioc)
    escalation = _escalation(level, risk, failures)

    return AnalystSummary(
        executive_summary=executive,
        threat_assessment=threat,
        observed_activity=observed,
        risk_rating=f"{risk.score}/100 - {level.value.upper()}",
        mitre_techniques=mitre,
        recommended_actions=actions,
        containment_recommendations=containment,
        escalation_guidance=escalation,
    )


# --------------------------------------------------------------------------- #
# Section builders
# --------------------------------------------------------------------------- #


def _executive(ioc: ValidatedIOC, risk: RiskAssessment, level: RiskLevel, provider_count: int) -> str:
    narrated_value = _narrate(ioc.value)
    base = (
        f"The indicator '{narrated_value}' ({ioc.ioc_type.value}) was analysed against "
        f"{provider_count} threat-intelligence provider(s) and received a risk score of "
        f"{risk.score}/100 ({level.value.upper()})."
    )
    if level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        return base + (
            " Multiple independent sources corroborate malicious activity; treat this as an "
            "active threat until disproven and initiate incident-response procedures."
        )
    if level == RiskLevel.MEDIUM:
        return base + " Evidence suggests suspicious activity but is not conclusive; contextual correlation is advised."
    if level == RiskLevel.LOW:
        return base + " Minor signals were observed; no immediate action required beyond standard monitoring."
    return base + " No significant threat signal was found. Absence of detections does not certify the indicator as benign."


def _threat_assessment(level: RiskLevel, usable: list[EnrichmentResult]) -> str:
    if not usable:
        return (
            "Threat assessment limited: no provider returned usable intelligence for this "
            "indicator. Coverage gaps may exist (free-tier limits, newly registered assets, "
            "or private-network addresses that public feeds never observe)."
        )
    positives = [e for e in usable if e.malicious is True]
    negatives = [e for e in usable if e.malicious is False]
    sentences = []
    if positives:
        sentences.append(
            f"{len(positives)} provider(s) assess this indicator as malicious: "
            # Provider findings quote the indicator verbatim; narrative slots
            # neutralise interpolated payload fragments before composition.
            + "; ".join(f"{p.provider}: {_narrate(p.summary)}" for p in positives[:3])
        )
    if negatives and not positives:
        sentences.append(
            "Available evidence leans benign: "
            + "; ".join(f"{n.provider}: {_narrate(n.summary)}" for n in negatives[:3])
        )
    if not positives and not negatives:
        sentences.append("Providers returned data but no definitive verdict; findings are ambiguous.")
    if level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        sentences.append(
            "Aggregated confidence is sufficient to justify proactive blocking while investigation proceeds."
        )
    return " ".join(sentences)


def _observed_activity(usable: list[EnrichmentResult]) -> list[str]:
    lines: list[str] = []
    for e in usable:
        lines.append(f"[{e.provider}] {e.summary or 'no summary'}")
        details = e.details or {}
        geo = details.get("country")
        isp = details.get("isp") or details.get("as_owner") or details.get("organization")
        if geo or isp:
            lines.append(f"[{e.provider}] Infrastructure context: country={geo or 'n/a'}, hosting={isp or 'n/a'}")
        first_seen = details.get("first_seen") or details.get("first_submission_date")
        last_seen = details.get("last_seen") or details.get("last_reported") or details.get("last_analysis_date")
        if first_seen or last_seen:
            lines.append(f"[{e.provider}] Observed window: first={first_seen or 'unknown'}, last={last_seen or 'unknown'}")
    if not lines:
        lines.append("No observable activity reported by configured providers.")
    return lines


def _recommended_actions(level: RiskLevel, ioc: ValidatedIOC) -> list[str]:
    generic = [
        "Correlate the indicator with SIEM telemetry (proxy, DNS, firewall, EDR) for the past 30 days.",
        "Record the analysis outcome in the case management system for auditability.",
    ]
    if level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        return [
            f"Block '{_narrate(ioc.value)}' at perimeter firewall/proxy immediately pending review.",
            "Hunt for related infrastructure (same ASN/hosting pattern) using pivot queries.",
            "Preserve raw provider responses for evidentiary chain-of-custody.",
        ] + generic
    if level == RiskLevel.MEDIUM:
        return [
            "Add to monitored blocklist (alert-only rule) rather than hard-blocking.",
            "Re-check reputation in 24-48h or after obtaining additional provider keys.",
        ] + generic
    return ["No blocking action warranted on current evidence."] + generic


def _containment(level: RiskLevel, ioc: ValidatedIOC) -> list[str]:
    target_kind = {
        "ipv4": "host address",
        "ipv6": "host address",
        "domain": "DNS resolution and web traffic",
        "url": "URL category / proxy policy",
        "email": "mail gateway filtering",
        "md5": "endpoint execution policy",
        "sha1": "endpoint execution policy",
        "sha256": "endpoint execution policy",
    }.get(ioc.ioc_type.value, "indicator")
    if level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        return [
            f"Deny all inbound/outbound traffic involving this {target_kind} on affected segments.",
            "Isolate potentially compromised endpoints that communicated with the indicator.",
            "Force credential resets for accounts that authenticated from/to this indicator.",
        ]
    if level == RiskLevel.MEDIUM:
        return [f"Apply alert-only inspection to this {target_kind}; escalate on repeat sightings."]
    return ["No containment required; retain indicator in watchlist only."]


def _escalation(level: RiskLevel, risk: RiskAssessment, failures: list[EnrichmentResult]) -> str:
    note = ""
    if failures:
        failed_names = ", ".join(sorted({f.provider for f in failures}))
        note = (
            f" NOTE: {len(failures)} provider check(s) failed ({failed_names}); "
            "the score may under-represent actual risk."
        )
    if level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        return (
            "Escalate to Incident Response lead within 1 hour; notify CISO on-call if "
            "production systems have confirmed communication with this indicator." + note
        )
    if level == RiskLevel.MEDIUM:
        return (
            "Assign to a Tier-2 analyst for contextual review within the shift; escalate "
            "to IR only upon corroborated endpoint behaviour." + note
        )
    return "Retain for trend analysis; no escalation required unless new evidence emerges." + note
