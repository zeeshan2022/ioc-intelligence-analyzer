# API Layer (Planned — v2.0)

> **Status: Not implemented in v1.0.0.** This directory is reserved for the FastAPI service layer introduced in Release 2.0.

## What lands here in v2.0

```
api/
├── app.py               # FastAPI application factory
├── routers/             # /analyze, /bulk-analyze, /report/{id}, /health, /version
├── auth.py              # Bearer-token authentication + RBAC scopes
├── schemas.py           # Pydantic request/response models
└── storage.py           # SQLite report persistence
```

## Design contract

The v2.0 API will be a **thin transport over the existing service seam** — `app.services.analyzer.AnalyzerService` — which is already stable and unit-tested in v1.0. No business logic will live in route handlers.

- Request/response shapes, error envelopes, and endpoint semantics are fully specified in **[docs/API_GUIDE.md](../docs/API_GUIDE.md)**.
- The deterministic risk engine, provider normalisation, and report renderers are reused unchanged.
- Authentication (API keys → OAuth2 in later minor releases) and rate limiting are enforced at this layer only; the CLI remains unauthenticated by design (local tool).

## Using the analyzer today (pre-v2.0)

Embed the service layer directly:

```python
from app.core.config import AppConfig
from app.services.analyzer import AnalyzerService

service = AnalyzerService(AppConfig.from_env())
assessment = service.analyze("203.0.113.66")   # returns IOCAssessment
```

Or drive the CLI from automation and consume the JSON report (`--format json`). See [docs/API_GUIDE.md § Part 1](../docs/API_GUIDE.md) for the invocation contract and exit-code table.

Do **not** add code to this directory until the v2.0 feature branch is opened.
