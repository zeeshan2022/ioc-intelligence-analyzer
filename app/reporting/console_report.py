"""Console (rich) renderer for Release 1 CLI output."""

from __future__ import annotations

from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from app.core.models import AnalysisResult, BulkAnalysisReport, RiskLevel

_LEVEL_STYLE = {
    RiskLevel.INFORMATIONAL: "bold cyan",
    RiskLevel.LOW: "bold green",
    RiskLevel.MEDIUM: "bold yellow",
    RiskLevel.HIGH: "bold dark_orange",
    RiskLevel.CRITICAL: "bold white on red",
}


def get_console(stderr: bool = False) -> Console:
    """Return a shared console; reports go to stdout, logs to stderr."""
    return Console(stderr=stderr)


def render_result(result: AnalysisResult, console: Console | None = None) -> None:
    """Print a single analysis as banner + tables."""
    console = console or get_console()
    level_style = _LEVEL_STYLE[result.risk.level]

    header = Text.assemble(
        ("IOC: ", "bold"), (result.ioc.value, "cyan bold"), ("   type: ", "dim"),
        (result.ioc.ioc_type.value, "magenta"), ("\nRisk: ", "bold"),
        (f"{result.risk.score}/100", level_style), ("  ", ""),
        (result.risk.level.value.upper(), level_style),
    )
    console.print(Panel(header, title="&#128737; IOC Intelligence Analyzer", box=ROUNDED, border_style="blue"))

    # Providers ----------------------------------------------------------- #
    table = Table(title="Threat Intelligence Providers", box=ROUNDED, title_justify="left")
    table.add_column("Provider", style="bold")
    table.add_column("Status")
    table.add_column("Conf.", justify="right")
    table.add_column("Verdict")
    table.add_column("Finding", overflow="fold", max_width=70)
    for e in result.enrichments:
        verdict = {True: "[red]MALICIOUS[/]", False: "[green]BENIGN[/]", None: "-"}[e.malicious]
        status = e.status.value
        style = {"ok": "green", "no_data": "grey58", "skipped": "grey58"}.get(status, "yellow")
        table.add_row(e.provider, f"[{style}]{status}[/]", str(e.confidence), verdict, e.summary or e.error or "")
    console.print(table)

    # Scoring -------------------------------------------------------------- #
    if result.risk.factors:
        sf = Table(title="Risk Score Breakdown", box=ROUNDED, title_justify="left")
        sf.add_column("Factor", style="bold")
        sf.add_column("Points", justify="right")
        sf.add_column("Evidence", overflow="fold", max_width=70)
        for f in result.risk.factors:
            color = "red" if f.points > 0 else "green"
            sf.add_row(f.name, f"[{color}]{f.points:+d}[/]", f.explanation)
        console.print(sf)

    # ATT&CK ---------------------------------------------------------------- #
    if result.summary.mitre_techniques:
        mt = Table(title="MITRE ATT&CK Mapping", box=ROUNDED, title_justify="left")
        mt.add_column("Tactic", style="bold")
        mt.add_column("ID")
        mt.add_column("Technique")
        for m in result.summary.mitre_techniques:
            mt.add_row(m.tactic, m.technique_id, m.technique_name)
        console.print(mt)

    console.print(Panel(result.summary.executive_summary, title="Executive Summary", border_style="blue"))
    console.print(Panel(result.summary.escalation_guidance, title="Escalation Guidance", border_style="magenta"))


def render_bulk(report: BulkAnalysisReport, console: Console | None = None) -> None:
    """Print a compact overview table for bulk runs."""
    console = console or get_console()
    table = Table(title=f"Bulk Analysis ({len(report.results)} analysed, {len(report.invalid_inputs)} rejected)", box=ROUNDED, title_justify="left")
    table.add_column("Indicator", overflow="fold", max_width=48)
    table.add_column("Type")
    table.add_column("Score", justify="right")
    table.add_column("Risk")
    for r in report.results:
        table.add_row(r.ioc.value, r.ioc.ioc_type.value, str(r.risk.score), Text(r.risk.level.value.upper(), _LEVEL_STYLE[r.risk.level]))
    console.print(table)
    if report.invalid_inputs:
        bad = Table(title="Rejected Inputs", box=ROUNDED, title_justify="left")
        bad.add_column("Input", overflow="fold", max_width=48)
        bad.add_column("Reason")
        for inv in report.invalid_inputs:
            bad.add_row(inv.value[:80], inv.reason)
        console.print(bad)
