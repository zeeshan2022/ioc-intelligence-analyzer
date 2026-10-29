# Dashboard (Planned — v3.0)

> **Status: Not implemented in v1.0.0.** This directory is reserved for the Streamlit analyst dashboard introduced in Release 3.0.

## What lands here in v3.0

```
dashboard/
├── streamlit_app.py     # Entry point (multi-page app)
├── pages/               # Triage queue, IOC detail, MITRE heatmap, history search
├── components/          # Reusable widgets (score gauge, evidence table)
└── data_access.py       # Read-only client over the v2.0 API / SQLite store
```

## Planned capabilities

| Capability | Description |
|---|---|
| Interactive triage queue | Bulk results ranked by score band with one-click drill-down |
| MITRE ATT&CK heatmaps | Technique frequency across an indicator set |
| Historical IOC search | Query previously analysed indicators (persisted via v2.0 storage) |
| Analytics views | Provider signal coverage, degradation rates, time-to-verdict |
| Report export | Re-render any stored assessment in HTML/JSON/MD/CSV |

## Security posture for the dashboard

- Consumes the **v2.0 authenticated API only** — no direct connector calls, no secrets in the browser tier.
- Inherits all v1.0 output-safety controls: narrative neutralisation, escaped evidence rendering, CSP headers.
- Read-only against the report store; write operations remain server-side.

## Today's equivalent

Generate an HTML report with the CLI and open it locally:

```bash
python main.py --ioc 203.0.113.66 --demo --format html --output reports/
```

The static HTML report is self-contained (inline CSS, no external assets) and safe to share internally.

Do **not** add code to this directory until the v3.0 feature branch is opened.
