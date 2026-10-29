# Database (Planned — v2.0)

> **Status: Not implemented in v1.0.0.** v1.0 is fully stateless: every run writes report files and exits. This directory is reserved for the persistence layer introduced alongside the v2.0 API.

## Why there is no database in v1.0

Deliberate design choice:

- **Auditability.** Reports are immutable artifacts on disk; no hidden state between runs.
- **Privacy.** Nothing sensitive is retained beyond what the operator explicitly saves.
- **Simplicity.** The CLI works air-gapped with zero infrastructure.

## Planned schema (v2.0, SQLite)

```sql
-- Sketch only; final DDL ships with v2.0 migrations
CREATE TABLE assessments (
    id          TEXT PRIMARY KEY,          -- ULID
    ioc_value   TEXT NOT NULL,             -- stored neutralised for display
    ioc_type    TEXT NOT NULL,
    score       INTEGER NOT NULL,
    level       TEXT NOT NULL,             -- INFORMATIONAL..CRITICAL
    created_at  TEXT NOT NULL,             -- ISO-8601 UTC
    payload     TEXT NOT NULL              -- full JSON report body
);
CREATE INDEX idx_assessments_ioc ON assessments (ioc_value);
CREATE INDEX idx_assessments_created ON assessments (created_at);
```

## Design rules for the future layer

1. **Store the JSON report verbatim** — the canonical machine-readable output of v1.0 renderers becomes the row payload; no re-modelling of enrichment data.
2. **Parameterised queries only** — indicator values are attacker-influenced input; string-built SQL is prohibited (covered by bandit in CI).
3. **No credentials in this directory.** Connection strings come from environment variables via `AppConfig`.
4. **Migration path** to PostgreSQL when multi-user deployments arrive (post-v3.0 decision).

Do **not** add code or `.db` files to this directory until the v2.0 feature branch is opened.
