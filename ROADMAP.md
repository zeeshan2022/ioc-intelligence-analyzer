# Roadmap

Direction of travel for IOC Intelligence Analyzer. Committed items appear in [docs/API_GUIDE.md](docs/API_GUIDE.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); everything below is planning, not contract.

---

## v1.0.0 — October 2026 (released) ✅
Hardened CLI: validation, VT/AbuseIPDB/GreyNoise enrichment, deterministic scoring, MITRE mapping, four report formats, bulk mode, privacy gates, XSS/CSV/traversal defences, Docker + CI/CD.
Residual: 3 non-blocking XSS-boundary test assertions (section-scoping polish) → fixed in **1.0.1** alongside first stub-provider enablement.

## v1.1 — Near-term hardening
- Resolve outstanding XSS-boundary assertion tests (scoping refinement, no behaviour change).
- Enable first real stubs: **DNS resolution** (most privacy-friendly) and **URLHaus** (keyless feed).
- Configurable scoring weights (governance-reviewed) without algorithm change.

## v2.0 — Service Platform *(committed design in API_GUIDE)*
- **FastAPI** service wrapping the unchanged `app.services` layer.
- **Authentication** (bearer tokens → OIDC later) and **RBAC** roles: analyst / engineer / admin.
- **SQLite persistence**: stored assessments, report retrieval by id, retention policy.
- **OpenAPI 3.1** auto-documentation; `/analyze`, `/bulk-analyze`, `/report/{id}`, `/health`, `/version`.
- Async bulk jobs with progress; webhook completion callbacks.
- Remaining stubs promoted: OTX, Shodan, WHOIS.

## v3.0 — Analyst Experience
- **Streamlit dashboard**: interactive triage queue, one-click IOC drill-down.
- **Analytics**: volume trends, band distributions, provider agreement metrics.
- **MITRE heatmaps**: technique frequency across assessments over time.
- **Historical IOC searches**: full-text + type-filtered query over persisted assessments.
- LLM-assisted refinement behind the existing MITRE interface (human-in-the-loop, evidence-preserving).

## v4.0 — SIEM/SOAR Ecosystem
- **Microsoft Sentinel**: Log Analytics Data Connector ingesting JSON assessments; analytics rules triggering playbooks on High/Critical bands.
- **Splunk**: CIM-adherent add-on / HEC exporter.
- **Elastic**: ECS mapping + ingest pipelines.
- **QRadar**: offense-compatible export adapter.
- Shared exporter framework so new SIEMs become configuration, not code.

## v5.0 — AI-Assisted Operations
- **AI Analyst Assistant**: conversational triage grounded strictly in stored evidence (no hallucinated intel; citations to score factors/provider rows mandatory).
- **Executive summaries** tuned per audience (SOC lead, CISO, board) from the same deterministic base.
- **Threat correlation**: cross-IOC relationship graph (shared infra, registrants, resolutions) surfaced automatically.
- **Natural-language queries**: "show critical IPs seen last week that talk to this domain" → filtered assessment search.

---

## Principles governing this roadmap
1. Determinism and explainability are never traded for cleverness.
2. Sanitisation policy (evidence vs narrative) extends to every new surface — API responses, dashboards, SIEM exports.
3. Score-model changes are release-decision events, not drive-by commits.
4. Privacy gates remain default-on in every deployment mode.

*Status markers: ✅ released · committed = normative design published · planning = intent.*
