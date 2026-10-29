# Sample Report — IOC Intelligence Analyzer v1.0.0

> **Documentation sample.** Representative Markdown output for a demo-mode analysis. Generated shape matches `python main.py --ioc 203.0.113.66 --demo --format markdown`.

---

# Threat Intelligence Report

**Indicator:** `203.0.113.66` · **Type:** IPv4 · **Generated:** 2026-10-29T00:00:00Z · **Tool:** ioc-intelligence-analyzer v1.0.0

## Executive Summary

Indicator **203.0.113.66** assessed **CRITICAL** (score **84/100**). Three independent providers corroborate malicious activity consistent with Mirai-family scanning infrastructure. Recommend perimeter block and outbound-hit hunt.

## Risk Assessment

| Field | Value |
|---|---|
| Score | **84 / 100** |
| Level | **CRITICAL** |

### Score Breakdown (explainable)

| Factor | Points | Rationale |
|---|---:|---|
| VirusTotal detections (malicious) | +30 | 12/80 engines flag this address as malicious. |
| AbuseIPDB confidence | +25 | 91% abuse confidence from 214 reports by 37 distinct users. |
| GreyNoise botnet activity | +20 | Classified malicious; associated with `mirai` botnet scanning. |
| Cross-provider corroboration | +9 | Two or more independent providers agree on malicious verdict. |

*Provider failures contribute zero points — risk is never inflated by missing data.*

## Provider Enrichment

| Provider | Status | Confidence | Key Signals |
|---|---|---:|---|
| VirusTotal | OK | 78 | malicious=12, suspicious=3, harmless=51 |
| AbuseIPDB | OK | 91 | abuse_confidence=91, reports=214, datacenter=true, tor=false |
| GreyNoise | OK | 65 | classification=malicious, botnet=mirai, seen_days=28 |

## MITRE ATT&CK Mapping

| Tactic | Technique | Rationale |
|---|---|---|
| Reconnaissance | T1595 — Active Scanning | GreyNoise classifies sustained unsolicited scanning from this source. |
| Command And Control | T1071 — Application Layer Protocol | Botnet association indicates potential C2 infrastructure. |

## Observed Activity (evidence, verbatim)

- *VirusTotal:* detected by engines tagged `malicious` on 2026-10-21.
- *AbuseIPDB:* most-reported abuse categories include `ssh`, `open-proxy`, `brute-force`.
- *GreyNoise:* actor label `Mirai scan campaign`; first-seen window 28 days.

## Recommended Actions

1. Block inbound traffic from this address at the perimeter for 30 days.
2. Hunt for outbound connections to this IP in the last 14 days.
3. Pivot on associated artefacts: port 23/2323 telnet scan signatures.

## Escalation Guidance

If outbound hits are found, escalate to IR under T1595/T1071 hypotheses; attach this report to the case record.

---

*Assumptions: demo-mode fixture data; no live provider calls were made for this sample. Private/reserved ranges are never sent to external providers.*
