"""HTML analyst report renderer.

Security-first templating: **all** dynamic values (IOC strings, provider
summaries, detector labels) are HTML-escaped before interpolation, so a hostile
indicator value such as ``"><script>...`` cannot break out of the document
(XSS via untrusted input). Reports are fully self-contained (inline CSS, no
external assets) so they can be emailed or archived safely.
"""

from __future__ import annotations

from html import escape
from pathlib import Path

from app.core.models import AnalysisResult, BulkAnalysisReport, RiskLevel
from app.reporting.utils import build_filename, ensure_output_dir, write_text_atomic

_LEVEL_COLORS = {
    RiskLevel.INFORMATIONAL: ("#0e7490", "#e0f2fe"),
    RiskLevel.LOW: ("#15803d", "#dcfce7"),
    RiskLevel.MEDIUM: ("#b45309", "#fef3c7"),
    RiskLevel.HIGH: ("#c2410c", "#ffedd5"),
    RiskLevel.CRITICAL: ("#b91c1c", "#fee2e2"),
}

_CSS = """
:root{--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--bg:#f8fafc;}
*{box-sizing:border-box}body{margin:0;font-family:'Segoe UI',system-ui,-apple-system,Arial,sans-serif;color:var(--ink);background:var(--bg);}
.container{max-width:1080px;margin:0 auto;padding:24px;}
header.report{background:#0f172a;color:#fff;border-radius:12px;padding:20px 24px;display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;}
header.report h1{font-size:20px;margin:0;} .brand small{color:#94a3b8;display:block;margin-top:4px;}
.badge{border-radius:999px;padding:6px 14px;font-weight:700;font-size:13px;letter-spacing:.4px;text-transform:uppercase;}
.meta{color:#cbd5e1;font-size:12px;margin-top:6px;}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-top:16px;box-shadow:0 1px 2px rgb(15 23 42 / 5%);}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.6px;color:#334155;margin:0 0 12px;border-bottom:1px solid var(--line);padding-bottom:8px;}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;}
.kv{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:13px;}
.kv b{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all;}
.scorebar{height:14px;border-radius:7px;background:#e2e8f0;overflow:hidden;margin:10px 0 4px;}
.scorebar>div{height:100%;border-radius:7px;}
table{width:100%;border-collapse:collapse;font-size:13px;}
th{text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid var(--line);padding:8px;}
td{border-bottom:1px solid var(--line);padding:9px 8px;vertical-align:top;}
.pill{display:inline-block;border-radius:999px;padding:2px 10px;font-size:11px;font-weight:700;}
.ok{background:#dcfce7;color:#166534}.warn{background:#fef3c7;color:#92400e}.err{background:#fee2e2;color:#991b1b}.skip{background:#e2e8f0;color:#475569}
ul,ol{margin:6px 0 0 18px;padding:0;}li{margin:5px 0;font-size:14px;}
blockquote{margin:12px 0 0;padding:12px 14px;background:#f1f5f9;border-left:4px solid #334155;border-radius:0 8px 8px 0;font-size:13px;color:#334155;}
footer{color:var(--muted);font-size:12px;margin:22px 4px;text-align:center;}
a{color:#1d4ed8;text-decoration:none}a:hover{text-decoration:underline}
@media print{body{background:#fff}.card{box-shadow:none;break-inside:avoid}}
"""


def _status_class(status_value: str) -> str:
    if status_value == "ok":
        return "ok"
    if status_value in {"no_data", "skipped"}:
        return "skip"
    if status_value in {"rate_limited", "timeout"}:
        return "warn"
    return "err"


def _neutralize_text(value: object) -> str:
    """Strip characters that enable HTML/XSS injection before escaping.

    Defence-in-depth on top of ``html.escape``: angle brackets and quotes are
    removed so hostile indicator values can never form markup (or re-enter an
    attribute context) even if a downstream consumer double-decodes the
    document. This guarantees no raw payload substring survives verbatim.
    """
    text = "" if value is None else str(value)
    for ch in "<>\"'&`":
        text = text.replace(ch, "")
    return text


def render_html(result: AnalysisResult) -> str:
    """Render one analysis into a standalone, XSS-safe HTML report."""
    fg, bg = _LEVEL_COLORS[result.risk.level]
    ioc = result.ioc
    summary = result.summary
    safe_value = _neutralize_text(ioc.value)  # used in <title>/header contexts

    factors_rows = "".join(
        f"<tr><td>{escape(_neutralize_text(f.name))}</td><td style='text-align:right;font-weight:700;"
        f'color={"#b91c1c" if f.points > 0 else "#15803d"}">{f.points:+d}</td>'
        f"<td>{escape(_neutralize_text(f.explanation))}</td></tr>"
        for f in result.risk.factors
    ) or "<tr><td colspan='3'>No scoring signals contributed.</td></tr>"

    provider_rows = "".join(
        "<tr>"
        f"<td><b>{escape(e.provider)}</b></td>"
        f"<td><span class='pill {_status_class(e.status.value)}'>{escape(e.status.value)}</span></td>"
        f"<td style='text-align:right'>{e.confidence}</td>"
        f"<td>{escape('MALICIOUS' if e.malicious is True else 'BENIGN' if e.malicious is False else '-')}</td>"
        f"<td>{escape(_neutralize_text(e.summary or e.error or ''))}"
        + (f" <a href='{escape(e.raw_ref)}' rel='noopener noreferrer' target='_blank'>source</a>" if e.raw_ref else "")
        + "</td></tr>"
        for e in result.enrichments
    )

    observed_items = "".join(f"<li>{escape(_neutralize_text(line))}</li>" for line in summary.observed_activity)
    mitre_rows = "".join(
        f"<tr><td>{escape(m.tactic)}</td><td class='mono'>{escape(m.technique_id)}</td>"
        f"<td>{escape(m.technique_name)}</td><td>{escape(_neutralize_text(m.rationale))}</td></tr>"
        for m in summary.mitre_techniques
    ) or "<tr><td colspan='4'>No defensible ATT&CK mapping derived from current evidence.</td></tr>"

    actions_items = "".join(f"<li>{escape(_neutralize_text(a))}</li>" for a in summary.recommended_actions)
    containment_items = "".join(f"<li>{escape(_neutralize_text(c))}</li>" for c in summary.containment_recommendations)

    meta_rows = "".join(
        f"<div class='kv'><b>{escape(str(k))}</b><span class='mono'>{escape(_neutralize_text(str(v)))}</span></div>"
        for k, v in ioc.metadata.items()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'">
<title>IOC Report - {escape(safe_value)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
  <header class="report">
    <div class="brand">
      <h1>&#128737; IOC Intelligence Analyzer</h1>
      <small>Analyst Threat Assessment Report &middot; v{escape(result.tool_version)}</small>
      <div class="meta">ID {escape(result.analysis_id)} &middot; Generated {escape(result.generated_at)} UTC</div>
    </div>
    <div style="text-align:right">
      <span class="badge" style="background:{bg};color:{fg};border:1px solid {fg}">{escape(result.risk.level.value)}</span>
      <div style="font-size:34px;font-weight:800;color:{fg};margin-top:6px">{result.risk.score}<span style="font-size:14px;color:#94a3b8">/100</span></div>
    </div>
  </header>

  <section class="card">
    <h2>Indicator Details</h2>
    <div class="kv" style="margin-bottom:12px"><b>Indicator of Compromise</b><span class="mono" style="font-size:15px">{escape(safe_value)}</span></div>
    <div class="grid">
      <div class="kv"><b>Type</b>{escape(ioc.ioc_type.value)}</div>
      {meta_rows}
    </div>
    <div class="scorebar"><div style="width:{result.risk.score}%;background:{fg}"></div></div>
    <blockquote>{escape(_neutralize_text(result.risk.explanation))}</blockquote>
  </section>

  <section class="card">
    <h2>Executive Summary</h2>
    <p style="font-size:14px;line-height:1.6">{escape(_neutralize_text(summary.executive_summary))}</p>
    <h2 style="margin-top:18px">Threat Assessment</h2>
    <p style="font-size:14px;line-height:1.6">{escape(_neutralize_text(summary.threat_assessment))}</p>
  </section>

  <section class="card">
    <h2>Risk Score Breakdown</h2>
    <table><thead><tr><th>Factor</th><th style="text-align:right">Points</th><th>Evidence</th></tr></thead>
    <tbody>{factors_rows}</tbody></table>
  </section>

  <section class="card">
    <h2>Provider Reputation Data</h2>
    <table><thead><tr><th>Provider</th><th>Status</th><th style="text-align:right">Confidence</th><th>Verdict</th><th>Finding</th></tr></thead>
    <tbody>{provider_rows}</tbody></table>
  </section>

  <section class="card">
    <h2>Observed Activity</h2><ul>{observed_items}</ul>
  </section>

  <section class="card">
    <h2>MITRE ATT&amp;CK Mapping</h2>
    <table><thead><tr><th>Tactic</th><th>ID</th><th>Technique</th><th>Rationale</th></tr></thead>
    <tbody>{mitre_rows}</tbody></table>
  </section>

  <section class="card">
    <h2>Recommended Actions</h2><ol>{actions_items}</ol>
    <h2 style="margin-top:18px">Containment Recommendations</h2><ul>{containment_items}</ul>
    <h2 style="margin-top:18px">Escalation Guidance</h2>
    <p style="font-size:14px">{escape(_neutralize_text(summary.escalation_guidance))}</p>
  </section>

  <footer>Generated by <b>ioc-intelligence-analyzer</b>. Provider data belongs to its respective owners
  (VirusTotal, AbuseIPDB, GreyNoise). Validate against internal telemetry before enforcement.</footer>
</div>
</body>
</html>
"""


def render_bulk_html(report: BulkAnalysisReport) -> str:
    """Concatenate per-IOC sections with a bulk overview header."""
    if not report.results:
        rows = "<tr><td colspan='4'>No valid indicators were analysed.</td></tr>"
    else:
        rows = "".join(
            f"<tr><td class='mono'>{escape(_neutralize_text(r.ioc.value))}</td><td>{escape(r.ioc.ioc_type.value)}</td>"
            f"<td style='text-align:right'>{r.risk.score}</td>"
            f"<td><span class='badge' style='background:{_LEVEL_COLORS[r.risk.level][1]};color:{_LEVEL_COLORS[r.risk.level][0]}'>"
            f"{escape(r.risk.level.value)}</span></td></tr>"
            for r in report.results
        )
    invalid_rows = "".join(
        f"<li><span class='mono'>{escape(_neutralize_text(inv.value[:80]))}</span> - {escape(_neutralize_text(inv.reason))}</li>"
        for inv in report.invalid_inputs
    )
    body_sections = "\n".join(_bulk_section_html(r) for r in report.results)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'">
<title>Bulk IOC Report</title><style>{_CSS}</style></head>
<body><div class="container">
<header class="report"><div class="brand"><h1>&#128737; Bulk IOC Intelligence Report</h1>
<small>{len(report.results)} indicator(s) analysed &middot; {len(report.invalid_inputs)} rejected</small>
<div class="meta">Report ID {escape(report.report_id)} &middot; {escape(report.generated_at)} UTC</div></div></header>
<section class="card"><h2>Overview</h2>
<table><thead><tr><th>Indicator</th><th>Type</th><th style="text-align:right">Score</th><th>Risk</th></tr></thead>
<tbody>{rows}</tbody></table>
{'<h2 style="margin-top:18px">Rejected Inputs</h2><ul>' + invalid_rows + '</ul>' if invalid_rows else ''}
</section>
{body_sections}
<footer>Generated by ioc-intelligence-analyzer.</footer>
</div></body></html>
"""


def _bulk_section_html(result: AnalysisResult) -> str:
    fg, bg = _LEVEL_COLORS[result.risk.level]
    return (
        '<section class="card">'
        f'<h2>{escape(_neutralize_text(result.ioc.value))}</h2>'
        f'<p><span class="badge" style="background:{bg};color:{fg}">{result.risk.score}/100 {escape(result.risk.level.value)}</span></p>'
        f'<p style="font-size:14px">{escape(_neutralize_text(result.summary.executive_summary))}</p>'
        "</section>"
    )


def write_html(
    result: AnalysisResult | BulkAnalysisReport,
    output_dir: Path,
    filename: str | None = None,
) -> Path:
    """Write an HTML report file and return its path."""
    out_dir = ensure_output_dir(Path(output_dir))
    if isinstance(result, BulkAnalysisReport):
        content = render_bulk_html(result)
        name = filename or f"bulk_{result.report_id[:8]}_report.html"
    else:
        content = render_html(result)
        name = filename or build_filename(result.ioc, "html")
    path = out_dir / name
    return write_text_atomic(path, content)
