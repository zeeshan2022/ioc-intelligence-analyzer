# Contributing to IOC Intelligence Analyzer

Thanks for your interest! This project is a security tool used by SOC teams; contributions are reviewed with that lens. Reading time ≈ 10 minutes.

## 1. Development Setup

```bash
git clone https://github.com/securitymonkey/ioc-intelligence-analyzer.git
cd ioc-intelligence-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # includes pytest, bandit, safety
cp .env.example .env                      # optional; --demo/--validate need no keys
./scripts/run_tests.sh                    # verbose run + coverage gate (>=80%)
```

Everything works offline: HTTP is mocked in tests; `python main.py --demo` exercises the full pipeline without keys.

## 2. Coding Standards

- Python 3.10+, type hints on public functions, `from __future__ import annotations` in modules.
- Line length ≤ 110 (see `[tool.ruff]` in pyproject.toml); docstrings on public APIs; small focused modules.
- Layering is sacred: `core` ← `connectors` ← `services` ← `reporting` ← `main.py`. Never import upward.
- New models go in `app/core/models.py` as frozen dataclasses/enums.
- Immutable scoring rules: **do not change `SCORING_RULES` weights or bands in a feature PR.** Weight changes require a governance-approved, versioned release decision (they alter customer risk output).
- The evidence/narrative sanitisation policy (SECURITY.md) is a contract: evidence → `html.escape`; narrative → `_neutralize_text`. New renderers must classify every interpolated field into one of these two buckets.

## 3. Testing Requirements

- Every PR keeps the suite green: `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q` (the env var is mandatory — CI sets it too).
- Coverage gate ≥ 80% (`fail_under = 80`); new code needs proportionate tests — bug fixes require a regression test that fails before the fix.
- Test placement: `tests/unit/…` (no network, fast) vs `tests/integration/…` (full pipeline with mocked HTTP only). Security-sensitive changes add cases to `tests/unit/test_reporting_security.py` using the existing parametrized payload fixtures.
- Markers available: `unit`, `integration`, `security`. Deprecation warnings from `app.*` are errors.
- No test may hit real provider APIs. Mock at the `requests` boundary (existing conftest helpers).

## 4. Pull Request Process

1. Branch from `main`: `feat/<scope>-<summary>`, `fix/<scope>-<summary>`, `docs/<summary>`.
2. One concern per PR. Keep diffs reviewable (< ~400 lines where possible).
3. Include in the description: motivation, behavior change, test evidence (pass/fail counts, coverage delta), and whether the evidence/narrative policy or scoring model is touched (should normally be *no*).
4. CI must pass: tests, coverage, bandit, safety. Maintainability/review follows.
5. Squash-merge with a conventional commit message (below). Release notes entries are drafted from commit messages — write them for changelog readers.

Breaking changes require an issue discussion and a minor/major version bump plan first.

## 5. Security Requirements

- **Never commit secrets.** Keys live in `.env` (git-ignored) or CI secrets. Pre-commit due diligence: `git diff --cached | grep -iE 'api[_-]?key|token|secret'`.
- New outbound calls must route through `BaseConnector` (timeout/retry/backoff inherited) and be added to the privacy-gate matrix if they can leak indicator data.
- New report formats must implement both sanitisation contexts and include XSS/CSV-injection tests.
- Dependencies are pinned; adding/upgrading one requires `safety` to pass and a short justification in the PR.
- Vulnerabilities discovered during development: follow [SECURITY.md](../SECURITY.md) — do not disclose in the PR.

## 6. Commit Message Standards

Conventional Commits:

```text
type(scope): imperative summary <= 72 chars

Optional body: what/why, not how. Reference issues (Fixes #123).

Types: feat | fix | docs | test | refactor | perf | build | ci | chore | security
Scopes: core | connectors | services | reporting | cli | docker | ci | docs
Examples:
  fix(core): enforce 63-char label cap in hostname validator
  security(reporting): neutralise javascript: scheme in narrative text
  docs(readme): add bulk-analysis examples
```

## 7. Getting Help

Open a regular issue for bugs/feature requests; use the security address for vulnerabilities. Maintainers triage weekly.

Happy hacking — and thank you for making defensive tooling trustworthy.
