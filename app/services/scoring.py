"""Deterministic risk-scoring engine.

Design principles
-----------------
* **Explainable**: every point awarded is recorded as a :class:`ScoreFactor`
  with a human-readable rationale; the final score is the clamped sum.
* **Provider-failure tolerant**: connector errors never add points; they are
  surfaced separately in reports so an outage cannot inflate risk.
* **Tunable**: weights live in one frozen table (:data:`SCORING_RULES`) and
  can later be loaded from configuration without touching the algorithm.

Documented rubric (Release 1):

===========================  ======
Signal                        Points
===========================  ======
VirusTotal malicious          +30
AbuseIPDB confidence         +25
Known botnet                 +20
Malware hosting              +15
Suspicious WHOIS             +10
===========================  ======

Additional calibrated signals (GreyNoise verdicts, multi-provider
corroboration) are documented inline below. Bands:

0-20 Informational · 21-40 Low · 41-60 Medium · 61-80 High · 81-100 Critical
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.models import EnrichmentResult, RiskAssessment, RiskLevel, ScoreFactor, score_to_level


@dataclass(frozen=True)
class ScoringRule:
    """One additive rule applied to normalised enrichment results."""

    name: str
    points: int
    predicate_key: str

    def explain(self, detail: str = "") -> str:
        return f"{self.name} (+{self.points}): {detail}" if detail else self.name


#: Central weight table. Keys are matched by dedicated detectors below.
SCORING_RULES: tuple[ScoringRule, ...] = (
    ScoringRule("VirusTotal detections", 30, "vt_malicious"),
    ScoringRule("AbuseIPDB abuse confidence", 25, "abuseipdb_confidence"),
    ScoringRule("Known botnet infrastructure", 20, "botnet"),
    ScoringRule("Malware hosting / delivery", 15, "malware_hosting"),
    ScoringRule("Suspicious registration data", 10, "suspicious_whois"),
    ScoringRule("GreyNoise malicious classification", 20, "greynoise_malicious"),
    ScoringRule("Multi-provider corroboration", 10, "corroboration"),
)

_MAX_SCORE = 100


def _has_provider(results: list[EnrichmentResult], provider: str) -> dict[str, EnrichmentResult]:
    return {r.provider: r for r in results if r.status.value in {"ok", "no_data"}}


def score_enrichments(ioc_value: str, ioc_type: str, results: list[EnrichmentResult]) -> RiskAssessment:
    """Compute a clamped 0-100 risk score with per-factor explanations.

    Args:
        ioc_value: Indicator being scored (used only in narrative text).
        ioc_type: Normalised IOC type string.
        results: Enrichment results from all attempted connectors.

    Returns:
        :class:`RiskAssessment` containing score, band, factors and a summary
        explanation suitable for embedding directly in analyst reports.
    """
    by_provider = _has_provider(results, "")
    factors: list[ScoreFactor] = []

    def add(rule_name: str, points: int, explanation: str) -> None:
        factors.append(ScoreFactor(name=rule_name, points=points, explanation=explanation))

    # ------------------------------------------------------------------ #
    # VirusTotal malicious verdicts
    # ------------------------------------------------------------------ #
    vt = by_provider.get("virustotal")
    if vt and vt.status.value == "ok":
        stats = (vt.details or {}).get("analysis_stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        if malicious > 0:
            points = min(30, 15 + 3 * malicious) if malicious <= 5 else 30
            add(
                "VirusTotal detections",
                points,
                f"{malicious} engine(s) flagged {ioc_value} as malicious"
                + (f" ({suspicious} additional suspicious)" if suspicious else ""),
            )
        elif suspicious >= 2:
            add("VirusTotal suspicious consensus", 10, f"{suspicious} engines returned suspicious verdicts")

    # ------------------------------------------------------------------ #
    # AbuseIPDB confidence
    # ------------------------------------------------------------------ #
    aidb = by_provider.get("abuseipdb")
    severe_categories: list[str] = []
    if aidb and aidb.status.value == "ok":
        details = aidb.details or {}
        severe_categories = [str(c) for c in (details.get("severe_categories") or [])]
        confidence = int(details.get("abuse_confidence_score", aidb.confidence) or 0)
        total_reports = int(details.get("total_reports", 0) or 0)
        whitelisted = bool(details.get("is_whitelisted"))

        if not whitelisted and confidence >= 50 and total_reports > 0:
            add(
                "AbuseIPDB abuse confidence",
                25,
                f"Confidence {confidence}% across {total_reports} abuse report(s)",
            )
        elif not whitelisted and confidence >= 25 and total_reports > 0:
            add(
                "AbuseIPDB moderate confidence",
                15,
                f"Confidence {confidence}% across {total_reports} abuse report(s)",
            )
        elif whitelisted:
            add("AbuseIPDB whitelist", -10, "Address is whitelisted by AbuseIPDB community curators")

        if details.get("is_tor"):
            add("Tor exit node", 5, "Traffic from this address may originate from the Tor network")

    # ------------------------------------------------------------------ #
    # Botnet signal (any provider)
    # ------------------------------------------------------------------ #
    botnet_hit = any(
        "botnet" in " ".join(str(item) for item in (res.details or {}).get("severe_categories", [])).lower()
        or "botnet" in str((res.details or {}).get("classification", "")).lower()
        or "botnet" in str(res.summary).lower()
        or "botnet" in " ".join(str(n) for n in (res.details or {}).get("malicious_detectors", [])).lower()
        for res in results
        if res.status.value == "ok"
    )
    if botnet_hit:
        add("Known botnet infrastructure", 20, "Provider data associates this indicator with botnet activity")

    # ------------------------------------------------------------------ #
    # Malware hosting / delivery signal
    # ------------------------------------------------------------------ #
    malware_hit = any(
        "malicious host" in " ".join(str(x).lower() for x in (res.details or {}).get("severe_categories", []))
        or "exploited host" in " ".join(str(x).lower() for x in (res.details or {}).get("severe_categories", []))
        or any(k in str(res.summary).lower() for k in ("malware", "trojan", "ransomware", "downloader", "stealer"))
        for res in results
        if res.status.value == "ok"
    )
    if malware_hit:
        add("Malware hosting / delivery", 15, "Indicator linked to malware hosting, staging or delivery")

    # ------------------------------------------------------------------ #
    # Suspicious WHOIS placeholder (connector lands in Release 2.x)
    # ------------------------------------------------------------------ #
    whois = by_provider.get("whois")
    if whois and whois.status.value == "ok":
        flags = (whois.details or {}).get("suspicious_flags") or []
        if flags:
            add("Suspicious registration data", 10, "WHOIS anomalies: " + ", ".join(map(str, flags)))

    # ------------------------------------------------------------------ #
    # GreyNoise classification
    # ------------------------------------------------------------------ #
    gn = by_provider.get("greynoise")
    if gn and gn.status.value == "ok":
        classification = str((gn.details or {}).get("classification", "")).lower()
        if classification == "malicious":
            actor = (gn.details or {}).get("actor") or "unknown actor"
            add("GreyNoise malicious classification", 20, f"GreyNoise classifies source as malicious ({actor})")
        elif classification == "benign":
            add("GreyNoise benign background noise", -10, "Activity matches widespread benign scanning patterns")

    # ------------------------------------------------------------------ #
    # Corroboration bonus: two or more providers independently say malicious
    # ------------------------------------------------------------------ #
    malicious_votes = sum(1 for r in results if r.status.value == "ok" and r.malicious is True)
    if malicious_votes >= 2:
        add(
            "Multi-provider corroboration",
            10,
            f"{malicious_votes} independent providers returned malicious verdicts",
        )

    raw_total = sum(f.points for f in factors)
    final_score = max(0, min(_MAX_SCORE, raw_total))
    level = score_to_level(final_score)

    explanation = _build_explanation(ioc_value, ioc_type, final_score, level, factors)

    return RiskAssessment(score=final_score, level=level, factors=factors, explanation=explanation)


def _build_explanation(
    value: str,
    ioc_type: str,
    score: int,
    level: RiskLevel,
    factors: list[ScoreFactor],
) -> str:
    if not factors:
        return (
            f"No threat-intelligence signal was found for {value} ({ioc_type}); "
            "score defaults to 0 (Informational). Absence of evidence is not "
            "evidence of absence - re-check provider coverage."
        )
    positives = [f for f in factors if f.points > 0]
    negatives = [f for f in factors if f.points < 0]
    parts = [
        f"Final score {score}/100 => {level.value.upper()} derived from "
        f"{len(positives)} positive signal(s)"
        + (f" and {len(negatives)} mitigating signal(s)" if negatives else "")
        + ": "
    ]
    parts.append("; ".join(f"{f.explanation} [+{f.points}]" if f.points > 0 else f"{f.explanation} [{f.points}]" for f in factors))
    return "".join(parts)
