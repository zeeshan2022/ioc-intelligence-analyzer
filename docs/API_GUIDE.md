# API Guide

**Scope:** Release 1 ships a hardened CLI. No HTTP service exists yet. This guide documents (a) the current programmatic/CLI interface that v2.0 will wrap, and (b) the committed REST design for FastAPI (v2.0) so integrators can plan today.

---

## Part 1 — Current Interface (v1.0, CLI)

### Invocation contract

```text
ioc-analyzer [--ioc IOC | --bulk FILE | --demo | --validate VALUE]
             [--format console,json,html,markdown,csv]
             [--output DIR] [--offline] [--log-level LEVEL] [--json-logs] [--version]
```

Exit codes: `0` success · `1` invalid arguments/target · `2` runtime/pipeline error.

### Python service layer (stable seam)

The CLI is a thin transport over importable services — safe to call directly from scripts/SOAR today:

```python
from app.core.config import AppConfig
from app.services.analyzer import Analyzer          # orchestration entry point
from app.reporting.json_report import render_json   # machine-readable artifact

cfg = AppConfig.from_env()                # reads VT_API_KEY etc.; repr redacts secrets
analyzer = Analyzer(cfg)
assessment = analyzer.analyze("203.0.113.66")       # -> RiskAssessment model

# assessment exposes: ioc, enrichments[], score, level, factors[], mitre[], summary
print(render_json([assessment]))
```

Guarantees carried forward into the REST API:
- `RiskAssessment` JSON schema stability (additive changes only across minor versions).
- Every enrichment row contains `provider`, `status` (`OK|SKIPPED|CONFIGURATION_ERROR|ERROR`), `details`, `error/reason`.
- Deterministic scoring: same inputs ⇒ same output byte-for-byte.

### Validation-only helper

```python
from app.core.ioc import validate_ioc, validate_many
validate_ioc("https://a.b/c")        # typed IOC or rejection reason
validate_many([...])                 # bulk: dedupe + partition, same validator paths
```

---

## Part 2 — Planned REST API (v2.0, FastAPI)

> Design commitments below are normative for v2.0; they exist here so consumers can integrate early behind feature flags.

### General

- Base path `/api/v1`, JSON everywhere, OpenAPI 3.1 auto-published at `/openapi.json` + Swagger UI at `/docs` (disableable for hardening).
- Auth: `Authorization: Bearer <token>` (static tokens in v2.0; OIDC later). RBAC roles: `analyst` (read/analyze), `engineer` (bulk/config), `admin`.
- Rate limiting per token; standard `Retry-After` on 429.
- All server-generated content inherits the evidence/narrative sanitisation policy — hostile IOCs remain visible but inert in responses and stored reports.

### Endpoints

#### `POST /analyze`
Single-indicator assessment.

```http
POST /api/v1/analyze
{ "ioc": "203.0.113.66", "offline": false, "formats": ["json"] }
```
`201` → full `RiskAssessment` object + `report_id`.
`422` → validation failure with machine-readable reason (mirrors CLI `--validate` semantics).
`403` → IOC type disallowed for caller role (e.g., analyst submitting email PII where policy forbids).

#### `POST /bulk-analyze`
File or array submission; async job model.

```http
POST /api/v1/bulk-analyze
{ "indicators": ["evil.example", "https://a.b/c"], "dedupe": true }
```
`202` → `{ "job_id": "...", "accepted": n, "invalid": m }` — note `invalid` excludes header tokens (`ioc`, `indicator`, `value`, `ioc_value`) exactly like the CLI bulk reader. Poll via `GET /report/{job_id}?kind=summary`.

#### `GET /report/{id}`
Retrieves stored assessment/report (SQLite persistence in v2.0). Supports `?format=json|html|markdown|csv`. `404` unknown/expired; `410` purged per retention policy.

#### `GET /health`
Liveness + dependency view (no auth): `{ "status": "ok", "providers": {"virustotal": "configured", "abuseipdb": "missing_key"} }`. Never leaks key material or values.

#### `GET /version`
`{ "app": "ioc-intelligence-analyzer", "version": "2.0.x", "schema": 1 }` for consumer compatibility checks.

### Error envelope (all endpoints)

```json
{ "error": { "code": "IOC_INVALID", "message": "label exceeds 63 characters", "field": "ioc" },
  "request_id": "..." }
```

### Mapping CLI → API

| CLI | API equivalent |
|---|---|
| `--ioc X` | `POST /analyze` |
| `--bulk file.csv` | `POST /bulk-analyze` |
| `--validate X` | dry-run flag on `/analyze` (`?validate=true`) |
| `--offline` | per-request `"offline": true` + server default policy |
| `reports/*.json` | `GET /report/{id}` |

### Integration notes for SOAR/SIEM today (pre-v2.0)

Run the CLI in a container or scheduled task and ingest `reports/*.json`:
```bash
docker compose run --rm analyzer --bulk /data/indicators.csv -f json
```
The JSON schema documented above is the same artifact — write parsers once, reuse them against the v2.0 REST response bodies.

---

*Roadmap context: [ROADMAP.md](../ROADMAP.md) · Architecture rationale: [ARCHITECTURE.md](ARCHITECTURE.md) §9*
