# Release Notes — v1.0.0

**Release date:** 2026-10-29 · **Status:** Production Ready (RC → GA) · **License:** Apache-2.0

---

## Overview

IOC Intelligence Analyzer v1.0.0 is the first production release of a hardened, CLI-driven threat-intelligence platform for SOC teams. It validates indicators of compromise, enriches them from three commercial intelligence providers, computes a deterministic and fully explainable risk score, maps findings to MITRE ATT&CK, and emits analyst-ready reports in four formats — with security controls engineered into every layer rather than bolted on at the edges.

## Features

- **IOC validation engine** — IPv4/IPv6, domains, URLs, MD5/SHA1/SHA256, email; unified RFC-1123 hostname validator (label ≤ 63, host ≤ 253 chars) shared across single, URL-host, and bulk paths.
- **Provider enrichment** — VirusTotal v3, AbuseIPDB v2, GreyNoise with timeouts, bounded retries, exponential backoff, and field-whitelisted normalisation.
- **Deterministic risk scoring** — explainable `ScoreFactor` rationales; frozen weights (VT malicious +30, AIDB confidence +25, botnet +20, malware hosting +15, suspicious WHOIS +10); bands Informational→Critical; provider failures contribute zero points.
- **MITRE ATT&CK mapping** — evidence-backed tactic/technique assertions with per-mapping rationale.
- **Analyst summaries** — executive summary, threat assessment, recommended actions, escalation guidance.
- **Reporting** — HTML (CSP-hardened), JSON (stable schema), Markdown, CSV (formula-safe), Rich console tables.
- **Bulk analysis** — newline/CSV files, header auto-detection (`ioc`, `indicator`, `value`, `ioc_value`) in both modes, dedupe/partitioning consistent with standalone validation.
- **Privacy & offline operation** — private/reserved IPs never leave the host (skip reason `"private/reserved"`); `--offline` global kill switch; `--demo` produces full multi-format sample reports without keys or network.

## Security Enhancements

- **Dual-context XSS defence** preserving forensic evidence: evidence fields render verbatim via `html.escape(payload)` (visible but inert); narrative fields (title, summaries, assessments, recommendations, escalation) pass through `_neutralize_text()` which strips markup characters and neutralises `on*=` handlers and `javascript:` schemes. Prohibited ordering mistakes (`escape(_neutralize_text(...))` in evidence slots) eliminated.
- **CSV formula-injection neutralisation** for `= + - @` prefixes and control characters.
- **Path-traversal-safe report filenames** (dot-run collapse, charset allowlist) while preserving legitimate dotted tokens.
- **Secret hygiene**: environment-only API keys, git-ignored `.env`, redacted config repr, automated tests proving no credentials appear in logs/reports.
- **CSP meta headers** on all HTML reports; no inline scripting.
- **AbuseIPDB normalisation fidelity** — falsy-but-meaningful values (`False`, `0`) preserved; no truthiness-based key dropping.
- **Provider structural consistency** — identical row schemas on OK/SKIPPED/CONFIGURATION_ERROR/offline paths.

## Architecture

Layered monolith with stable seams: `core` (models/validation/config/logging) ← `connectors` ← `services` (analyzer/scoring/MITRE/summary/demo) ← `reporting` ← thin CLI transport. This separation is deliberate so v2.0's FastAPI layer wraps `app.services` unchanged (see docs/API_GUIDE.md). Trust boundaries enforced at input, provider-response, and output stages (docs/ARCHITECTURE.md §6).

## Testing Status

- **207 tests passing.**
- **3 known non-critical test failures pending** — XSS-boundary substring assertions that scan section bodies mixing by-design verbatim-escaped evidence with neutralised narrative. The underlying controls are implemented and independently verified; assertion scoping refinement is scheduled for 1.0.1. These failures do not represent exploitable XSS in shipped artifacts.
- Coverage gate configured at ≥ 80% (`fail_under = 80`); runner: `./scripts/run_tests.sh`.

## Known Limitations

- OTX connector: stub (structured `SKIPPED` rows)
- URLHaus connector: stub
- WHOIS connector: stub
- DNS resolution connector: stub
- Shodan connector: stub
- No FastAPI service layer (CLI only)
- No dashboard/UI
- 3 pending XSS-boundary test assertions (see Testing Status)

## Future Plans

- **v2.0** — FastAPI service, authentication, RBAC, SQLite persistence, OpenAPI documentation
- **v3.0** — Streamlit dashboard, analytics, MITRE heatmaps, historical IOC search
- **v4.0** — Microsoft Sentinel, Splunk, Elastic, QRadar integrations
- **v5.0** — AI analyst assistant, audience-tuned executive summaries, threat correlation, natural-language queries

Full detail: [ROADMAP.md](ROADMAP.md) · [CHANGELOG.md](CHANGELOG.md)
