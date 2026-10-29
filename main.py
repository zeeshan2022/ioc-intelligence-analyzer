"""Command-line interface for the IOC Intelligence Analyzer (Release 1 / Phase 1).

Usage examples::

    python main.py --ioc 8.8.8.8
    python main.py --ioc malicious-domain.com -f html,json
    python main.py --bulk indicators.csv --output ./reports
    python main.py --demo            # offline sample report, no API keys needed

Exit codes
----------
0  success
2  invalid input / usage error
3  fatal internal error (unexpected)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from app import __version__
from app.core.config import AppConfig
from app.core.logging import setup_logging
from app.reporting.console_report import get_console, render_bulk, render_result
from app.reporting.csv_report import write_csv
from app.reporting.html_report import write_html
from app.reporting.json_report import write_json
from app.reporting.markdown_report import write_markdown
from app.services.analyzer import IOCAnalyzer
from app.services.demo import build_demo_report, build_demo_result

VALID_FORMATS = {"json", "html", "markdown", "csv", "console"}

_WRITERS = {
    "json": write_json,
    "html": write_html,
    "markdown": write_markdown,
    "csv": write_csv,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ioc-analyzer",
        description=(
            "IOC Intelligence Analyzer - aggregate threat intelligence for IPs, "
            "domains, URLs, hashes and emails, score risk and produce analyst reports."
        ),
        epilog="API keys are read from environment variables (VT_API_KEY, ABUSEIPDB_API_KEY, GREYNOISE_API_KEY) or a local .env file.",
    )
    target = parser.add_mutually_exclusive_group(required=False)
    target.add_argument("--ioc", "-i", help="Single indicator to analyse (IP, domain, URL, hash or email).")
    target.add_argument("--bulk", "-b", metavar="FILE", help="Path to a newline/CSV file containing one indicator per line.")
    target.add_argument("--demo", action="store_true", help="Generate an offline sample report (no network, no API keys).")
    target.add_argument("--validate", metavar="VALUE", help="Validate an indicator format without enrichment.")

    parser.add_argument(
        "--format",
        "-f",
        default="console,json,html,markdown,csv",
        help="Comma-separated outputs: console,json,html,markdown,csv (default: all).",
    )
    parser.add_argument("--output", "-o", type=Path, default=None, help="Report output directory (default: ./reports).")
    parser.add_argument("--offline", action="store_true", help="Skip all external provider calls.")
    parser.add_argument("--log-level", default=None, help="DEBUG|INFO|WARNING|ERROR (default: INFO).")
    parser.add_argument("--json-logs", action="store_true", help="Emit structured JSON logs to stderr.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _parse_formats(raw: str) -> list[str]:
    formats: list[str] = []
    for token in raw.split(","):
        name = token.strip().lower()
        if not name:
            continue
        if name == "md":
            name = "markdown"
        if name not in VALID_FORMATS:
            raise ValueError(f"unknown format '{token}'. Valid: {', '.join(sorted(VALID_FORMATS))}")
        if name not in formats:
            formats.append(name)
    return formats or ["console"]


def _resolve_output_dir(args: argparse.Namespace, config: AppConfig) -> Path:
    return args.output if args.output else config.report_output_dir


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point; returns a process exit code (never raises SystemExit internally)."""
    parser = build_parser()
    # ``exit=False`` keeps argparse errors recoverable so we control exit codes.
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        formats = _parse_formats(args.format)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not any([args.ioc, args.bulk, args.demo, args.validate]):
        parser.print_help(sys.stderr)
        print("\nerror: provide --ioc, --bulk, --demo or --validate", file=sys.stderr)
        return 2

    config = AppConfig.from_env()
    if args.offline:
        # Rebuild with offline flag forced (AppConfig is immutable/frozen).
        config = AppConfig(
            vt_api_key=config.vt_api_key,
            abuseipdb_api_key=config.abuseipdb_api_key,
            greynoise_api_key=config.greynoise_api_key,
            connectors=config.connectors,
            offline_mode=True,
            log_level=config.log_level,
            report_output_dir=config.report_output_dir,
        )

    log_level = args.log_level or config.log_level
    setup_logging(level=log_level, json_logs=args.json_logs)
    console = get_console()

    # --- validate-only mode ---------------------------------------------- #
    if args.validate is not None:
        from app.core.ioc import validate_ioc

        result = validate_ioc(args.validate)
        payload = result.to_dict()
        if payload["valid"]:
            console.print(f"[green]VALID[/green]  {payload['value']}  [dim]type={payload['ioc_type']}[/dim]")
            for k, v in payload["metadata"].items():
                console.print(f"       [dim]{k}=[/dim]{v}")
        else:
            console.print(f"[red]INVALID[/red] {payload['reason']}")
        if "json" in formats:
            out_dir = _resolve_output_dir(args, config)
            path = out_dir / f"validation_{result.ioc_type.value}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            import json as _json

            path.write_text(_json.dumps(payload, indent=2), encoding="utf-8")
            console.print(f"[dim]wrote {path}[/dim]")
        return 0 if payload["valid"] else 2

    analyzer = IOCAnalyzer(config)

    # --- demo mode --------------------------------------------------------- #
    if args.demo:
        bulk = build_demo_report()
        single = bulk.results[0]
        _emit(bulk, single, formats, _resolve_output_dir(args, config), console)
        console.print("[yellow]Demo report generated from canned data - no live provider calls were made.[/yellow]")
        return 0

    # --- single IOC -------------------------------------------------------- #
    if args.ioc:
        result = analyzer.analyze(args.ioc)
        if result is None:
            console.print(f"[red]Invalid indicator:[/red] {args.ioc!r} - see --validate for details")
            return 2
        _emit(result, result, formats, _resolve_output_dir(args, config), console)
        return 0

    # --- bulk ------------------------------------------------------------- #
    try:
        bulk_report = analyzer.analyze_file(Path(args.bulk))
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2
    if not bulk_report.results:
        console.print("[red]No valid indicators found in input file.[/red]")
        render_bulk(bulk_report, console)
        return 2
    _emit(bulk_report, bulk_report.results[0], formats, _resolve_output_dir(args, config), console)
    return 0


def _emit(bulk_target, primary, formats: list[str], output_dir: Path, console) -> None:
    """Render requested formats; ``primary`` drives console output."""
    if "console" in formats:
        from app.core.models import BulkAnalysisReport

        if isinstance(bulk_target, BulkAnalysisReport):
            render_bulk(bulk_target, console)
            if len(bulk_target.results) == 1:
                render_result(primary, console)
        else:
            render_result(primary, console)

    writers = [f for f in formats if f in _WRITERS]
    if not writers:
        return
    from app.core.models import BulkAnalysisReport

    subject = bulk_target if isinstance(bulk_target, BulkAnalysisReport) else primary
    for fmt in writers:
        path = _WRITERS[fmt](subject, output_dir)
        console.print(f"[dim]wrote {fmt:<8} report -> {path}[/dim]")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001 - top-level boundary
        print(f"fatal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(3)
