# Security Policy

The IOC Intelligence Analyzer is a security tool; we hold ourselves to the standards we build against. This document describes how to report vulnerabilities, what to expect from us, and the security controls already embedded in the product.

## Supported Versions

| Version | Supported | Notes |
|---|---|---|
| 1.0.x (current) | ✅ | Active branch for security fixes |
| < 1.0 pre-releases | ❌ | Not supported; upgrade required before triage |

Security fixes ship as patch releases (1.0.1, 1.0.2 …) and are announced in [CHANGELOG.md](CHANGELOG.md).

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

1. Email **security@ioc-analyzer.example** (replace with maintainer contact when published) with:
   - Description of the issue and affected component (`app/core`, `app/connectors`, `app/reporting`, CLI, Docker/CI).
   - Reproduction steps or proof-of-concept (sanitised — no live customer IOCs).
   - Potential impact and, if known, remediation ideas.
2. For findings that require full confidentiality, request PGP key details in your initial mail.
3. Sensitive indicators under investigation must never be included in reports — use RFC5737/RFC2606 documentation ranges (`203.0.113.0/24`, `evil.example`).

### Response Expectations

| Stage | Commitment |
|---|---|
| Acknowledgement | ≤ 72 hours |
| Initial triage & severity (CVSS v4) | ≤ 7 days |
| Fix timeline for High/Critical | ≤ 30 days (patch or documented mitigation) |
| Advisory publication | With the fix release, after coordinated disclosure window |

We follow responsible disclosure: reporters get a 90-day private window (extendable on request) before public advisory; credit is given unless declined.

### Safe Harbor

Research conducted in good faith under this policy is authorised. We will:
- Not initiate or support legal action against researchers who avoid data destruction, privacy violations, and service disruption;
- Treat reports as evidence of good faith;
- Work with you to determine scope if questions arise.

Out of scope: social engineering, physical attacks, DoS testing, third-party provider vulnerabilities (report those to VirusTotal/AbuseIPDB/GreyNoise directly), and findings requiring leaked credentials.

## Security Design Highlights

These controls are implemented, tested, and enforced by CI:

- **Private IP protection** — RFC1918, loopback and link-local addresses are detected before enrichment and never transmitted to external providers.
- **Reserved IP protection** — reserved/documentation ranges follow normal provider paths but are explicitly annotated; skip reasons are stable strings (`"private/reserved"`).
- **XSS protection with forensic fidelity** — dual-policy rendering: *evidence* fields (IOC values, indicator details, provider artifacts) preserve payloads verbatim via `html.escape()` so analysts see exactly what was observed while remaining inert; *narrative* fields (title, executive summary, threat assessment, recommendations, escalation guidance) pass through `_neutralize_text()`, which strips markup characters and neutralises `on*=` event handlers and `javascript:` schemes. Ordering mistakes such as double-handling evidence slots are prohibited and covered by parametrized payload tests.
- **CSV injection protection** — spreadsheet formula prefixes (`=`, `+`, `-`, `@`) and control characters are neutralised in every CSV cell at render time.
- **Path traversal defence** — IOC-derived filenames are sanitised (dot-run collapse, charset allowlist) so hostile inputs cannot escape the report directory; single dots inside legitimate tokens (e.g., `203.0.113.66`) are preserved.
- **Secret redaction** — API keys exist only in environment variables/`.env` (git-ignored); configuration repr redacts them; automated tests assert no key material appears in logs or any report format.
- **Secure logging** — structured JSON or human logs to stderr, level-controlled; no secrets, no raw provider bodies beyond whitelisted normalised fields.
- **Content Security Policy** — HTML reports carry CSP meta headers and contain no inline scripting.
- **Bounded network behaviour** — per-request timeouts, capped retries with exponential backoff; global `--offline` kill switch.
- **Supply-chain hygiene** — pinned dependencies, `bandit` static analysis, `safety` vulnerability audit, and Trivy image scanning in CI.

## Known Limitations (accept the risk consciously)

- OTX/URLHaus/Shodan/WHOIS/DNS connectors are stubs returning structured `SKIPPED` rows — no intelligence loss is silently hidden, but coverage is limited to VT/AIDB/GN.
- No authentication/authorisation layer exists because there is no server yet (CLI only). Do not expose reports over unauthenticated shares.
- 3 non-blocking XSS-boundary assertion tests remain pending polish; all shipped controls above are functional and independently verified. See CHANGELOG "Known Issues".

## Auditing This Project

- Run the test suite yourself: `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q`
- Static checks: `bandit -r app main.py -ll` · `safety check`
- Container scan: `trivy image ioc-intelligence-analyzer:1.0.0`

Thank you for helping keep downstream SOC users safe.
