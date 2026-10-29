"""CSV report renderer (spreadsheet / ingest friendly).

One row per analysis with flattened key fields plus a per-provider detail CSV.
All cells are neutralised against CSV formula injection (OWASP): leading
``=``, ``+``, ``-``, ``@``, tab and CR characters are escaped with an apostrophe.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from app.core.models import AnalysisResult, BulkAnalysisReport
from app.reporting.utils import build_filename, ensure_output_dir, write_text_atomic

_SUMMARY_FIELDS = [
    "analysis_id",
    "generated_at",
    "ioc_value",
    "ioc_type",
    "risk_score",
    "risk_level",
    "verdict",
    "providers_ok",
    "providers_failed",
    "mitre_techniques",
    "executive_summary",
    "escalation_guidance",
]

_DETAIL_FIELDS = [
    "analysis_id",
    "ioc_value",
    "provider",
    "status",
    "confidence",
    "malicious",
    "summary",
    "raw_ref",
    "error",
]


def _neutralize(value: object) -> str:
    """Escape spreadsheet formula-injection vectors in a CSV cell."""
    text = "" if value is None else str(value)
    if text[:1] in {"=", "+", "-", "@", "\t", "\r"}:
        text = "'" + text
    return text.replace("\n", " ").replace("\r", " ")


def summarize_row(result: AnalysisResult) -> dict[str, str]:
    data = result.to_dict()
    ok = sum(1 for e in result.enrichments if e.status.value == "ok")
    failed = sum(1 for e in result.enrichments if e.status.is_failure)
    verdicts = [e.malicious for e in result.enrichments if e.status.value == "ok"]
    if any(v is True for v in verdicts):
        verdict = "MALICIOUS"
    elif verdicts and all(v is False for v in verdicts):
        verdict = "BENIGN"
    elif verdicts:
        verdict = "UNKNOWN"
    else:
        verdict = "NO_DATA"
    techniques = ", ".join(f"{m.technique_id}" for m in result.summary.mitre_techniques)
    return {
        "analysis_id": result.analysis_id,
        "generated_at": result.generated_at,
        "ioc_value": data["ioc"]["value"],
        "ioc_type": data["ioc"]["ioc_type"],
        "risk_score": str(data["risk"]["score"]),
        "risk_level": data["risk"]["level"],
        "verdict": verdict,
        "providers_ok": str(ok),
        "providers_failed": str(failed),
        "mitre_techniques": techniques or "",
        "executive_summary": result.summary.executive_summary,
        "escalation_guidance": result.summary.escalation_guidance,
    }


def render_csv(report: BulkAnalysisReport) -> str:
    """Render the summary CSV for a bulk report (also valid for single runs)."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_SUMMARY_FIELDS, lineterminator="\n")
    writer.writeheader()
    for res in report.results:
        writer.writerow({k: _neutralize(v) for k, v in summarize_row(res).items()})
    return buf.getvalue()


def render_provider_detail_csv(report: BulkAnalysisReport) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_DETAIL_FIELDS, lineterminator="\n")
    writer.writeheader()
    for res in report.results:
        for enr in res.enrichments:
            writer.writerow(
                {
                    "analysis_id": res.analysis_id,
                    "ioc_value": _neutralize(res.ioc.value),
                    "provider": enr.provider,
                    "status": enr.status.value,
                    "confidence": enr.confidence,
                    "malicious": "" if enr.malicious is None else str(enr.malicious),
                    "summary": _neutralize(enr.summary),
                    "raw_ref": _neutralize(enr.raw_ref),
                    "error": _neutralize(enr.error),
                }
            )
    return buf.getvalue()


def write_csv(
    report: BulkAnalysisReport | AnalysisResult,
    output_dir: Path,
    filename: str | None = None,
) -> Path:
    out_dir = ensure_output_dir(Path(output_dir))
    if isinstance(report, AnalysisResult):
        bulk = BulkAnalysisReport(results=[report])
    else:
        bulk = report
    name = filename or build_filename(bulk.results[0].ioc, "csv") if bulk.results else "bulk_report.csv"
    content = render_csv(bulk) + "\n# --- provider detail ---\n" + render_provider_detail_csv(bulk)
    path = out_dir / name
    return write_text_atomic(path, content)
