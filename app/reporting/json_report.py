"""JSON report renderer (machine-readable, SIEM/soar friendly)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.models import AnalysisResult, BulkAnalysisReport
from app.reporting.utils import build_filename, ensure_output_dir, write_text_atomic


def render_json(result: AnalysisResult) -> str:
    """Serialise one analysis result to pretty-printed JSON."""
    return json.dumps(result.to_dict(), indent=2, sort_keys=False, ensure_ascii=True)


def render_bulk_json(report: BulkAnalysisReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=True)


def write_json(
    result: AnalysisResult | BulkAnalysisReport,
    output_dir: Path,
    filename: str | None = None,
) -> Path:
    """Write a JSON report; returns the final path."""
    out_dir = ensure_output_dir(Path(output_dir))
    if isinstance(result, BulkAnalysisReport):
        content = render_bulk_json(result)
        name = filename or f"bulk_{result.report_id[:8]}_report.json"
    else:
        content = render_json(result)
        name = filename or build_filename(result.ioc, "json")
    path = out_dir / name
    return write_text_atomic(path, content + "\n")


def load_json_report(path: Path) -> dict[str, Any]:
    """Convenience loader used by dashboards/tests."""
    return json.loads(Path(path).read_text(encoding="utf-8"))
