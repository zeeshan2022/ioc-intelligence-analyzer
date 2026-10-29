# Bulk IOC Intelligence Report

- **Report ID:** `190f88a2-f980-4ce7-88e1-9edeb384b816`
- **Generated (UTC):** 2026-10-29T07:11:35+00:00
- **Analysed:** 2 · **Rejected inputs:** 0

# IOC Intelligence Report - `203.0.113.66`

- **Analysis ID:** `57eaf1af-61cb-4e42-a298-99da65cbf431`
- **Generated (UTC):** 2026-10-29T07:11:35+00:00
- **Tool version:** 1.0.0
- **IOC type:** ipv4
- **Risk score:** **100/100** (CRITICAL)

## Executive Summary

The indicator '203.0.113.66' (ipv4) was analysed against 3 threat-intelligence provider(s) and received a risk score of 100/100 (CRITICAL). Multiple independent sources corroborate malicious activity; treat this as an active threat until disproven and initiate incident-response procedures.

## Threat Assessment

3 provider(s) assess this indicator as malicious: virustotal: 14/72 engines flagged as malicious; 3 suspicious; labels: Trojan.Win32, Generic.Malware.AI, Heuristic; abuseipdb: Abuse confidence 95% from 214 reports; 41 distinct reporters; categories: Botnet, SSH, Brute Force; greynoise: Classification: malicious; Actor: demo-botnet-scanner; Categories: scanner, exploit Aggregated confidence is sufficient to justify proactive blocking while investigation proceeds.

## Risk Score Breakdown

| Factor | Points | Explanation |
|---|---:|---|
| VirusTotal detections | +30 | 14 engine(s) flagged 203.0.113.66 as malicious (3 additional suspicious) |
| AbuseIPDB abuse confidence | +25 | Confidence 95% across 214 abuse report(s) |
| Known botnet infrastructure | +20 | Provider data associates this indicator with botnet activity |
| Malware hosting / delivery | +15 | Indicator linked to malware hosting, staging or delivery |
| GreyNoise malicious classification | +20 | GreyNoise classifies source as malicious (demo-botnet-scanner) |
| Multi-provider corroboration | +10 | 3 independent providers returned malicious verdicts |

> Final score 100/100 => CRITICAL derived from 6 positive signal(s): 14 engine(s) flagged 203.0.113.66 as malicious (3 additional suspicious) [+30]; Confidence 95% across 214 abuse report(s) [+25]; Provider data associates this indicator with botnet activity [+20]; Indicator linked to malware hosting, staging or delivery [+15]; GreyNoise classifies source as malicious (demo-botnet-scanner) [+20]; 3 independent providers returned malicious verdicts [+10]

## Provider Findings

| Provider | Status | Confidence | Verdict | Summary |
|---|---|---:|---|---|
| virustotal | ok | 68 | MALICIOUS | 14/72 engines flagged as malicious; 3 suspicious; labels: Trojan.Win32, Generic.Malware.AI, Heuristic |
| abuseipdb | ok | 95 | MALICIOUS | Abuse confidence 95% from 214 reports; 41 distinct reporters; categories: Botnet, SSH, Brute Force |
| greynoise | ok | 80 | MALICIOUS | Classification: malicious; Actor: demo-botnet-scanner; Categories: scanner, exploit |

## Observed Activity

- [virustotal] 14/72 engines flagged as malicious; 3 suspicious; labels: Trojan.Win32, Generic.Malware.AI, Heuristic
- [virustotal] Infrastructure context: country=NL, hosting=DEMO-NETWORK-64500 (synthetic)
- [abuseipdb] Abuse confidence 95% from 214 reports; 41 distinct reporters; categories: Botnet, SSH, Brute Force
- [abuseipdb] Infrastructure context: country=NL, hosting=Demo Hosting B.V.
- [abuseipdb] Observed window: first=unknown, last=2026-10-28T03:11:52Z
- [greynoise] Classification: malicious; Actor: demo-botnet-scanner; Categories: scanner, exploit
- [greynoise] Infrastructure context: country=Netherlands, hosting=Demo Hosting B.V.
- [greynoise] Observed window: first=2026-09-14, last=2026-10-28

## MITRE ATT&CK Mapping

| Tactic | Technique | Rationale |
|---|---|---|
| Command and Control | T1071 - Application Layer Protocol | abuseipdb evidence matched 'botnet|c2|command[- ]and[- ]control|cobalt\s?strike|meterpreter|beacon' on: Abuse confidence 95% from 214 reports; 41 distinct reporters; categories: Botnet, SSH, Brute Force | Botnet | SSH | Brute Force | Botnet |
| Initial Access | T1190 - Exploit Public-Facing Application | abuseipdb evidence matched 'exploit|vulnerab|payload|shellshock|log4j|rce' on: Abuse confidence 95% from 214 reports; 41 distinct reporters; categories: Botnet, SSH, Brute Force | Botnet | SSH | Brute Force | Botnet |
| Credential Access | T1110 - Brute Force | abuseipdb evidence matched 'brute[- ]?force|password spray|credential stuffing|rdp brute' on: Abuse confidence 95% from 214 reports; 41 distinct reporters; categories: Botnet, SSH, Brute Force | Botnet | SSH | Brute Force | Botnet |
| Command and Control | T1090 - Proxy | greynoise evidence matched 'tor|onion|i2p' on: Classification: malicious; Actor: demo-botnet-scanner; Categories: scanner, exploit | scanner | exploit | demo-botnet-scanner | malicious |
| Discovery | T1595 - Active Scanning | greynoise evidence matched 'scanner|scanning|probe|masscan|zmap' on: Classification: malicious; Actor: demo-botnet-scanner; Categories: scanner, exploit | scanner | exploit | demo-botnet-scanner | malicious |

## Recommended Actions

1. Block '203.0.113.66' at perimeter firewall/proxy immediately pending review.
2. Hunt for related infrastructure (same ASN/hosting pattern) using pivot queries.
3. Preserve raw provider responses for evidentiary chain-of-custody.
4. Correlate the indicator with SIEM telemetry (proxy, DNS, firewall, EDR) for the past 30 days.
5. Record the analysis outcome in the case management system for auditability.

## Containment Recommendations

- Deny all inbound/outbound traffic involving this host address on affected segments.
- Isolate potentially compromised endpoints that communicated with the indicator.
- Force credential resets for accounts that authenticated from/to this indicator.

## Escalation Guidance

Escalate to Incident Response lead within 1 hour; notify CISO on-call if production systems have confirmed communication with this indicator.

---
_Generated by ioc-intelligence-analyzer. Verify with primary telemetry before enforcement._

# IOC Intelligence Report - `example.org`

- **Analysis ID:** `8c912df3-3ced-4316-bc9e-a5d76f203eee`
- **Generated (UTC):** 2026-10-29T07:11:35+00:00
- **Tool version:** 1.0.0
- **IOC type:** domain
- **Risk score:** **0/100** (INFORMATIONAL)

## Executive Summary

The indicator 'example.org' (domain) was analysed against 1 threat-intelligence provider(s) and received a risk score of 0/100 (INFORMATIONAL). No significant threat signal was found. Absence of detections does not certify the indicator as benign.

## Threat Assessment

Available evidence leans benign: virustotal: 0/72 engines flagged as malicious

## Risk Score Breakdown

| Factor | Points | Explanation |
|---|---:|---|
| _no signals_ | 0 | No provider signal contributed |

> No threat-intelligence signal was found for example.org (domain); score defaults to 0 (Informational). Absence of evidence is not evidence of absence - re-check provider coverage.

## Provider Findings

| Provider | Status | Confidence | Verdict | Summary |
|---|---|---:|---|---|
| virustotal | ok | 0 | BENIGN | 0/72 engines flagged as malicious |
| abuseipdb | skipped | 0 | - | AbuseIPDB does not support 'domain' indicators |
| greynoise | skipped | 0 | - | GreyNoise does not support 'domain' indicators |

## Observed Activity

- [virustotal] 0/72 engines flagged as malicious

## MITRE ATT&CK Mapping

_No defensible ATT&CK mapping derived from current evidence._

## Recommended Actions

1. No blocking action warranted on current evidence.
2. Correlate the indicator with SIEM telemetry (proxy, DNS, firewall, EDR) for the past 30 days.
3. Record the analysis outcome in the case management system for auditability.

## Containment Recommendations

- No containment required; retain indicator in watchlist only.

## Escalation Guidance

Retain for trend analysis; no escalation required unless new evidence emerges.

---
_Generated by ioc-intelligence-analyzer. Verify with primary telemetry before enforcement._
