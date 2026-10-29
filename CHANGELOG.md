# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

---

## [1.0.0] — 2026-10-29

First production release: hardened CLI threat-intelligence analyzer.

### Added
- **IOC validation engine** (`app/core/ioc.py`): IPv4, IPv6, domain, URL, MD5/SHA1/SHA256, email detection and strict validation; unified `_is_valid_hostname()` (RFC-1123 shape, label ≤ 63 chars, hostname ≤ 253 chars) shared by domain, URL-host and bulk (`validate_many`) paths; deterministic dedupe/partitioning for bulk input.
- **Provider connectors:** VirusTotal v3, AbuseIPDB v2, GreyNoise — bounded retries with exponential backoff, per-request timeouts, field-whitelisted normalisation into a common `EnrichmentResult` schema. Statuses: `OK`, `SKIPPED`, `CONFIGURATION_ERROR`, `ERROR`.
- **Structured stubs** with identical row shape: AlienVault OTX, URLHaus, Shodan, WHOIS, DNS resolution.
- **Deterministic risk engine** (`app/services/scoring.py`): explainable `ScoreFactor` rationales; frozen weights (VT malicious +30, AbuseIPDB confidence +25, botnet +20, malware hosting +15, suspicious WHOIS +10, calibrated corroboration); bands 0–20 Informational / 21–40 Low / 41–60 Medium / 61–80 High / 81–100 Critical; provider failures contribute zero points.
- **MITRE ATT&CK mapping** with evidence-backed tactic/technique assertions and per-mapping rationale.
- **Analyst summaries:** executive summary, threat assessment, recommended actions, escalation guidance.
- **Report renderers:** HTML (CSP-hardened), JSON, Markdown, CSV; console tables via Rich.
- **CLI:** `--ioc`, `--bulk`, `--demo`, `--validate`, `--format`, `--output`, `--offline`, `--log-level`, `--json-logs`, `--version`; exit-code contract.
- **Bulk file reader** with header auto-detection (`ioc`, `indicator`, `value`, `ioc_value`) applied consistently in CSV and plain-text modes.
- **Privacy gate:** private/reserved address detection with stable skip reason `"private/reserved"`; no egress for internal space.
- **Test suite:** 210 tests (unit + integration + security class); coverage configuration with `fail_under = 80`; `scripts/run_tests.sh`.
- **Documentation:** README, ARCHITECTURE, INSTALL, API_GUIDE, THREAT_INTELLIGENCE_SOURCES, CONTRIBUTING, SECURITY, ROADMAP, release notes.
- **DevSecOps:** Dockerfile (non-root UID 10001, healthcheck), docker-compose, GitHub Actions (ci, security, docker), example indicator files and sample outputs.

### Security
- Dual-context XSS policy: evidence fields rendered with `html.escape(payload)` verbatim (forensic fidelity, inert execution); narrative fields (title, executive summary, threat assessment, observed-activity prose, recommendations, escalation guidance) rendered through `_neutralize_text()`, which strips `<>"'&\`` and neutralises `on*=` event-handler patterns and `javascript:` schemes. Double-ordering (`escape(_neutralize_text(...))`) prohibited in evidence slots.
- CSV formula-injection neutralisation (`= + - @` prefixes, control characters) at cell level.
- Path-traversal-safe report filenames (dot-run collapse, charset allowlist) preserving legitimate dotted tokens.
- Secret hygiene: env-only API keys, git-ignored `.env`, redacted config repr, tests asserting no credential material in logs/reports.
- Content-Security-Policy meta headers on HTML reports; no inline JavaScript.
- Bounded network behaviour (timeouts, capped retries, backoff) mitigating SSRF-adjacent amplification and hangs.
- AbuseIPDB normalisation preserves falsy-but-meaningful values (`False`, `0`) — no truthiness-based key dropping.

### Testing
- Baseline progression stabilised across the release cycle: 191 → 200 → 201 → 206 → **207 passing**.
- Parametrized XSS payload corpus, CSV-injection vectors, filename traversal cases, provider-consistency schema checks, bulk header/dedupe scenarios, band-boundary unit tests.
- **Statement coverage: 92%** of `app/` (target ≥ 80% exceeded; `fail_under = 80` retained).

### Dependencies (security)
- `requests` 2.32.4 → **2.33.0** (patches CVE-2026-25645, insecure temporary-file reuse).
- `python-dotenv` 1.1.1 → **1.2.2** (patches CVE-2026-28684, arbitrary file overwrite via symlink handling).
- Post-bump verification: full suite re-run green-equivalent (207 passed / 3 known pending), `safety check --file requirements.txt` clean, bandit 0 high / 0 medium.

### Known Issues
- **3 non-blocking XSS-boundary assertion failures** remain in `tests/unit/test_reporting_security.py::test_script_and_event_handlers_are_escaped` (and related section-scope variants). Root cause: substring assertions scan whole-section bodies that legitimately mix evidence (verbatim-escaped payload, by design) with narrative (neutralised). Controls themselves are correct and verified; the assertion scoping needs refinement in a follow-up patch. These failures do **not** indicate exploitable XSS in shipped reports. Scheduled for resolution in 1.0.1.
- OTX / URLHaus / Shodan / WHOIS / DNS connectors are stubs returning structured `SKIPPED` rows.
- No REST API (planned v2.0) and no dashboard (planned v3.0).

---

Pre-1.0.0 development history tracked in repository history; no earlier tagged releases.
