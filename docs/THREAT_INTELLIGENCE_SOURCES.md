# Threat Intelligence Sources

This document describes every intelligence source the analyzer integrates with (or is designed to integrate with), what data it returns, how it influences risk scoring, rate-limit realities, and privacy implications.

**Status legend:** ✅ Active in v1.0 · 🧩 Stub (structured `SKIPPED` rows, roadmap implementation)

---

## Active Providers (Release 1)

### 1. VirusTotal ✅

| Aspect | Detail |
|---|---|
| **Purpose** | Multi-engine malware/URL/IP reputation; the primary detection-coverage signal in the risk model. |
| **API** | v3 REST (`https://www.virustotal.com/api/v3`), header `x-apikey`. Endpoint used: `/ip_addresses/{ip}`, `/domains/{domain}`, `/urls/{id}` (URL id = base64url of the URL). |
| **Data returned (normalised)** | `malicious` engine count, total engines, detection categories/labels, last-analysis verdicts, reputation tags. Whitelisted into `EnrichmentResult.details` — unexpected vendor keys are dropped at the connector boundary. |
| **Risk impact** | **Malicious verdicts → +30 points** (largest single weight). Detection labels also feed MITRE mapping (e.g., Cobalt Strike beacon labels → T1071/T1059 rationales). |
| **Rate limits** | Free tier: ~4 requests/min, 500/day. The connector honours timeouts and bounded retries with exponential backoff; sustained 429s surface as `ERROR` rows (never score inflation). |
| **Privacy considerations** | Queries disclose which indicators your organisation is investigating. VT may share submissions with security vendors under its ToU. **Never query internal/private addresses** — the analyzer enforces this via the private/reserved gate before any egress. Treat sensitive corporate domains as potentially exposed when submitted. |

### 2. AbuseIPDB ✅

| Aspect | Detail |
|---|---|
| **Purpose** | Community-reported IP abuse: SSH brute-force, scanning, fraud, bot activity — strongest IP-confidence signal. |
| **API** | v2 (`https://api.abuseipdb.com/api/v2/check`), header `Key`, query params `ipAddress`, `maxAgeInDays`, `verbose`. |
| **Data returned (normalised)** | `abuse_confidence_score` (0–100), total & recent report counts, attack type categories (with verbose flags such as `is_tor_exit_node`, `is_cloud_provider`), country/ISP/usage-type context. Normalisation preserves falsy-but-meaningful values (`False`, `0`) — keys are never dropped by truthiness filtering. |
| **Risk impact** | **Confidence ≥ threshold → +25 points**; category-driven corroboration adds calibrated inline signals. Categories map to ATT&CK tactics (brute force → Credential Access T1110; scanning → Discovery T1595). |
| **Rate limits** | Free tier: 1,000 requests/day per key. Bulk mode naturally throttles via sequential processing plus retry caps. |
| **Privacy considerations** | Sends the queried IP to a third party (unavoidable for IP reputation). Only routable addresses reach the API. Do not use for customer-attributable IPs without legal review; check GDPR/privacy policy where end-user IPs are involved. |

### 3. GreyNoise ✅

| Aspect | Detail |
|---|---|
| **Purpose** | Distinguishes mass internet background noise (scanners, bots) from targeted activity; classifies actor behaviour and detects Tor infrastructure. |
| **API** | Community/Enterprise REST (`https://api.greynoise.io/v3/community/{ip}` or enterprise riot endpoint), header `key`. |
| **Data returned (normalised)** | `classification` ∈ {`benign`, `susicious`→normalised `suspicious`, `malicious`}, `bot` flag, `actor` name, `reason`/`details`, Tor indicator. |
| **Risk impact** | Calibrated verdict weights: **known botnet involvement → +20**, malicious hosting classification → **+15**, suspicious verdict contributes to the low/medium bands; `benign` classifications suppress corroboration bonuses so scanner noise cannot inflate scores. Bot/actor names drive MITRE C2/T1090 mappings. |
| **Rate limits** | Community tier: ~1 request/sec, limited daily quota. Enterprise tier removes most constraints. Connector handles 429/timeout as `ERROR` rows with zero score contribution. |
| **Privacy considerations** | Same IP-disclosure profile as AbuseIPDB. GreyNoise only needs the address, never surrounding case context — a deliberate design property (no IOC metadata beyond the value itself is transmitted). |

---

## How Enrichment Degradation Works (all providers)

Every provider path emits an identical row structure:

| Status | Meaning | Score effect |
|---|---|---|
| `OK` | Live answer received | weighted factors applied |
| `CONFIGURATION_ERROR` | API key missing/empty | 0 points, explicit in reports |
| `SKIPPED` | Offline mode, private/reserved IP, or unsupported IOC type | 0 points, reason string included (e.g. `"private/reserved"`) |
| `ERROR` | Network/HTTP failure after bounded retries | 0 points, error surfaced for audit |

A provider outage can therefore **never** change a risk band — by design.

---

## Future Sources (implemented as structured stubs today)

### AlienVault OTX 🧩
Planned pulses, indicator relationships, and CVE-linked intelligence. Expected role: corroborating signal (+calibrated), expanded MITRE coverage via pulse tags. Privacy: shares queried indicators with OTX community telemetry.

### URLHaus (abuse.ch) 🧩
Malware-hosting URL and payload database keyed by URL/host/hash. Expected role: direct URL+hash verdicts; strong Initial Access / Execution technique evidence. Public feed — no authentication currently required; minimal privacy exposure.

### Shodan 🧩
Passive reconnaissance context: open services, banners, host history for IPs. Expected role: exposure-surface weighting (e.g., management interfaces on public IPs) and supporting evidence for T1595/T1046. Requires paid API key; queries are passive-side, disclosing only the target IP.

### WHOIS Lookup 🧩
Registration age, registrar, redaction status, nameserver patterns. Expected role: **Suspicious registration signals → +10** (already represented in the rubric); new-registered-domain heuristics for phishing campaigns. Note: outbound RDAP/WHOIS queries leak the domain you are investigating to registries.

### DNS Resolution 🧩
Current A/AAAA/MX/NS records, historical resolution plausibility, subdomain enumeration sanity. Expected role: liveness validation, fast-flux detection, and typosquat correlation. Runs against your configured resolver — no third-party intel vendor sees the query, making it the most privacy-friendly enrichment planned.

All stubs already return structurally consistent `SKIPPED` rows, so enabling one is a connector-body change only — scoring, MITRE, summary and renderers require no modification.

---

## Provider Comparison Matrix

| Capability | VirusTotal | AbuseIPDB | GreyNoise | OTX | URLHaus | Shodan | WHOIS | DNS |
|---|---|---|---|---|---|---|---|---|
| IP reputation | ✅ | ✅ | ✅ | ✅ | – | ✅ | – | – |
| Domain/URL | ✅ | – | – | ✅ | ✅ | – | ✅ | ✅ |
| Hash/file | ✅ | – | – | ✅ | ✅ | – | – | – |
| Email | – | – | – | ✅ | – | – | – | ✅ (MX) |
| Tor/anonymiser | – | flag | ✅ | – | – | – | – | – |
| Bot/mass-scan context | – | categories | ✅✅ | – | – | – | – | – |
| Infra exposure | – | – | – | – | – | ✅✅ | – | – |
| Registration age | – | – | – | – | – | – | ✅✅ | – |
| Key needed today | yes | yes | yes | – | – | – | – | – |

## Choosing Keys & Tiers (operational guidance)

- **SOC triage volume:** start free tiers everywhere; AbuseIPDB + GreyNoise community cover IP-heavy workflows; VT free tier suffices for spot checks.
- **Bulk feeds (>500 IOCs/day):** upgrade VT and GreyNoise first (rate limits bind before data quality does).
- **Air-gapped/regulatory environments:** run `--offline`; assessments still produce validated IOCs with explicit `SKIPPED` provenance rows.

*See [ARCHITECTURE.md](ARCHITECTURE.md) §8 for how to add a provider, and [SECURITY.md](../SECURITY.md) for disclosure policy.*
