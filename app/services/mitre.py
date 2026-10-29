"""MITRE ATT&CK enrichment mapping.

Maps normalised provider findings to ATT&CK tactics/techniques using the
published enterprise matrix IDs (https://attack.mitre.org). Release 1 performs
*deterministic keyword/classification mapping*; an LLM-assisted refinement is
planned for Release 3 (see docs/ROADMAP.md) behind the same interface.

Mapping philosophy: only assert techniques that a defensible evidence trail
supports (provider categories, actor names, detection labels). Each mapping
carries its rationale so SOC analysts can accept/reject it during triage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.core.models import EnrichmentResult, MitreTechnique


@dataclass(frozen=True)
class _Pattern:
    """One regex -> ATT&CK technique rule."""

    pattern: re.Pattern[str]
    tactic: str
    technique_id: str
    technique_name: str


#: Ordered rule table; first match per (tactic, id) wins.
_RULES: tuple[_Pattern, ...] = (
    # Command & Control ------------------------------------------------- #
    _Pattern(re.compile(r"botnet|c2|command[- ]and[- ]control|cobalt\s?strike|meterpreter|beacon", re.I),
             "Command and Control", "T1071", "Application Layer Protocol"),
    _Pattern(re.compile(r"tor|onion|i2p", re.I),
             "Command and Control", "T1090", "Proxy"),
    _Pattern(re.compile(r"dnsteal|dns[- ]tunnel|dns query", re.I),
             "Command and Control", "T1071.004", "DNS"),
    # Initial Access ---------------------------------------------------- #
    _Pattern(re.compile(r"exploit|vulnerab|payload|shellshock|log4j|rce", re.I),
             "Initial Access", "T1190", "Exploit Public-Facing Application"),
    _Pattern(re.compile(r"phishing|spearphish|malspam|credential[- ]harvest", re.I),
             "Initial Access", "T1566", "Phishing"),
    _Pattern(re.compile(r"drive[- ]?by|watering[- ]?hole", re.I),
             "Initial Access", "T1189", "Drive-by Compromise"),
    # Credential Access -------------------------------------------------- #
    _Pattern(re.compile(r"brute[- ]?force|password spray|credential stuffing|rdp brute", re.I),
             "Credential Access", "T1110", "Brute Force"),
    # Exfiltration ------------------------------------------------------- #
    _Pattern(re.compile(r"exfiltrat|data theft|staging server|upload to", re.I),
             "Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    # Persistence / hosting ----------------------------------------------#
    _Pattern(re.compile(r"malware host|malicious host|dropper|downloader|payload delivery|secondary stage", re.I),
             "Persistence", "T1105", "Ingress Tool Transfer"),
    _Pattern(re.compile(r"scanner|scanning|probe|masscan|zmap", re.I),
             "Discovery", "T1595", "Active Scanning"),
)


def map_techniques(results: list[EnrichmentResult]) -> list[MitreTechnique]:
    """Derive defensible ATT&CK mappings from enrichment evidence.

    Args:
        results: Normalised connector outputs for one IOC.

    Returns:
        Deduplicated list of :class:`MitreTechnique` with evidence rationale.
    """
    seen: set[tuple[str, str]] = set()
    techniques: list[MitreTechnique] = []

    for res in results:
        if res.status.value != "ok":
            continue
        haystacks: list[str] = [res.summary]
        details = res.details or {}
        for key in ("severe_categories", "report_categories", "categories", "malicious_detectors", "actor", "classification"):
            value = details.get(key)
            if isinstance(value, list):
                haystacks.extend(str(v) for v in value)
            elif value:
                haystacks.append(str(value))
        blob = " | ".join(h for h in haystacks if h)

        for rule in _RULES:
            if rule.pattern.search(blob):
                key = (rule.tactic, rule.technique_id)
                if key in seen:
                    continue
                seen.add(key)
                techniques.append(
                    MitreTechnique(
                        tactic=rule.tactic,
                        technique_id=rule.technique_id,
                        technique_name=rule.technique_name,
                        rationale=f"{res.provider} evidence matched '{rule.pattern.pattern}' on: {blob[:160]}",
                    )
                )

    return techniques
