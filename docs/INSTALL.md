# Installation Guide — IOC Intelligence Analyzer

Target platforms: Linux (primary), macOS, Windows. Python **3.10+** required (developed/tested on 3.10–3.12).

---

## 1. Prerequisites

| Requirement | Minimum | Verify with |
|---|---|---|
| Python | 3.10 | `python3 --version` |
| pip | bundled with 3.10+ | `python3 -m pip --version` |
| Git | any recent | `git --version` |
| Outbound HTTPS | to `virustotal.com`, `abuseipdb.com`, `api.greynoise.io` | not required for `--offline`/`--demo` |
| Disk | ~50 MB (venv + deps) | – |

No database, no system services, no admin rights needed.

## 2. Obtain the Source

```bash
git clone https://github.com/securitymonkey/ioc-intelligence-analyzer.git
cd ioc-intelligence-analyzer
```

## 3. Virtual Environment (strongly recommended)

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
py -m venv .venv
.venv\Scripts\Activate.ps1
```

## 4. Install Dependencies

Option A — pinned requirements (recommended for reproducibility):

```bash
pip install -r requirements.txt
```

Option B — install as a package (adds the `ioc-analyzer` console command):

```bash
pip install .
```

For development (test + security tooling):

```bash
pip install -r requirements.txt --upgrade   # includes pytest, bandit, safety
# or
pip install ".[dev]"
```

## 5. Environment Variables

Create your local config (never commit `.env` — it is git-ignored):

```bash
cp .env.example .env
```

| Variable | Required? | Purpose | Default |
|---|---|---|---|
| `VT_API_KEY` | for live VT enrichment | VirusTotal v3 key | empty → VT returns `CONFIGURATION_ERROR` row |
| `ABUSEIPDB_API_KEY` | for live AIDB | AbuseIPDB v2 key | empty → graceful skip row |
| `GREYNOISE_API_KEY` | for live GN | GreyNoise key | empty → graceful skip row |
| `IOC_LOG_LEVEL` | no | DEBUG/INFO/WARNING/ERROR/CRITICAL | INFO |
| `IOC_JSON_LOGS` | no | structured JSON logs to stderr | false |
| `IOC_REPORT_DIR` | no | report output directory | reports |
| `IOC_OFFLINE` | no | force global offline | false |
| `IOC_TIMEOUT_SECONDS` | no | per-request HTTP timeout | 15 |
| `IOC_MAX_RETRIES` | no | bounded retries | 3 |
| `IOC_BACKOFF_FACTOR` | no | exponential backoff multiplier | 0.7 |

The application starts successfully with **zero** keys — missing keys produce explicit `CONFIGURATION_ERROR` rows instead of crashes.

## 6. API Key Setup

| Provider | Registration | Notes |
|---|---|---|
| VirusTotal | https://www.virustotal.com/gui/my-apikey | free tier: 4 req/min, 500/day — respect limits |
| AbuseIPDB | https://www.abuseipdb.com/account/api | free tier adequate for triage volumes |
| GreyNoise | https://viz.greynoise.io/account/api-key | community key covers basic queries |

Key handling rules:
- Store keys **only** in `.env` or your secret manager / process environment.
- Keys are never logged, never written into reports, and the config object redacts them in its repr.
- Rotate immediately if a key is ever pasted into a ticket, chat, or repository.

## 7. Verification Steps

Run these in order — each isolates a layer:

```bash
# 1. Entry point responds
python main.py --version

# 2. Validator works without any network/key
python main.py --validate "https://a.b/c"
python main.py --validate "999.1.1.1"        # expected: INVALID (octet range)

# 3. Offline pipeline produces all four report formats
python main.py --demo
ls reports/                                   # expect .html .json .md .csv artifacts

# 4. Full test suite (no network access required — HTTP is mocked)
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q

# 5. Live smoke test (requires keys)
python main.py --ioc 8.8.8.8                  # benign IP, expect low/informational band
```

Success criteria: step 3 writes four files under `reports/`; step 4 exits with the suite passing; step 5 prints a scored assessment table.

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `CONFIGURATION_ERROR` rows in reports | provider key missing | set key in `.env`; confirm with `printenv VT_API_KEY` inside activated shell |
| All providers skipped despite keys set | `IOC_OFFLINE=true` or `--offline` passed | remove flag/env var |
| HTTP 429 / rate-limit errors | free-tier quotas exceeded | raise interval, upgrade plan, or use `--offline` for format work |
| TLS/proxy errors in corporate networks | egress inspection | set standard `HTTPS_PROXY`/`REQUESTS_CA_BUNDLE` env vars (requests honours them) |
| `ModuleNotFoundError: requests` | venv not activated | `source .venv/bin/activate` and reinstall requirements |
| Reports land in wrong folder | relative `--output` from another cwd | pass absolute `-o /path/to/reports` or set `IOC_REPORT_DIR` |
| Private IP shows no enrichment | **by design** | RFC1918/loopback/link-local are never sent externally; see SECURITY.md |
| Test failures mentioning plugin autoload | external pytest plugins loaded | always run with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` (as CI does) |
| Coverage gate fails (<80%) | partial test selection | run the whole suite via `./scripts/run_tests.sh` |

Still stuck? Open an issue with the sanitized log output (`--json-logs` helps) — never include API keys in the report.

---

**Next steps:** [Usage examples](../README.md#usage) · [Architecture](ARCHITECTURE.md) · [Threat intel sources](THREAT_INTELLIGENCE_SOURCES.md)
