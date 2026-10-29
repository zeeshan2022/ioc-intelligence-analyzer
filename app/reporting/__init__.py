"""Report generation package (JSON / HTML / Markdown / CSV).

Release 1 focuses on polished HTML reports; the other formats share the same
:class:`AnalysisResult` model so adding SIEM-friendly outputs costs nothing.
"""

from app.reporting.csv_report import render_csv, write_csv
from app.reporting.html_report import render_html, write_html
from app.reporting.json_report import render_json, write_json
from app.reporting.markdown_report import render_markdown, write_markdown

__all__ = [
    "render_csv",
    "render_html",
    "render_json",
    "render_markdown",
    "write_csv",
    "write_html",
    "write_json",
    "write_markdown",
]
