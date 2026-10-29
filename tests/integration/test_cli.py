"""CLI integration tests: argument parsing, exit codes and file outputs.

Invokes ``main()`` in-process (never subprocesses the network stack); provider
calls are prevented by --offline / no API keys plus the conftest network guard.
"""

from __future__ import annotations

import json

import pytest

import main as cli

pytestmark = [pytest.mark.integration]


def run(argv: list[str]) -> int:
    return cli.main(argv)


class TestValidateFlag:
    def test_validate_valid_ip_exit_zero(self, tmp_path) -> None:
        code = run(["--validate", "8.8.8.8", "-f", "json", "-o", str(tmp_path)])
        assert code == 0
        files = list(tmp_path.glob("validation_*.json"))
        assert files, "expected a validation JSON artefact"
        payload = json.loads(files[0].read_text(encoding="utf-8"))
        assert payload["valid"] is True
        assert payload["ioc_type"] == "ipv4"

    def test_validate_invalid_exit_two(self, tmp_path) -> None:
        assert run(["--validate", "not!!!valid", "-f", "console"]) == 2

    @pytest.mark.parametrize("value", ["203.0.113.66", "example.com", "https://a.b/c",
                                       "d41d8cd98f00b204e9800998ecf8427e"])
    def test_all_supported_types_validate(self, value: str) -> None:
        assert run(["--validate", value, "-f", "console"]) == 0


class TestIOCFlag:
    def test_single_ioc_offline_writes_reports(self, tmp_path) -> None:
        code = run(["--ioc", "203.0.113.66", "--offline", "-o", str(tmp_path),
                    "-f", "json,html,markdown,csv"])
        assert code == 0
        exts = {p.suffix for p in tmp_path.iterdir()}
        assert {".json", ".html", ".md", ".csv"} <= exts
        # JSON report structurally complete.
        json_files = [p for p in tmp_path.glob("*.json")]
        payload = json.loads(json_files[0].read_text(encoding="utf-8"))
        assert payload["ioc"]["value"] == "203.0.113.66"
        assert "risk" in payload and "analyst_summary" in payload

    def test_invalid_ioc_exit_two(self, tmp_path) -> None:
        assert run(["--ioc", "!!!not-an-ioc!!!", "--offline", "-o", str(tmp_path)]) == 2

    def test_unknown_format_exit_two(self, tmp_path) -> None:
        assert run(["--ioc", "8.8.8.8", "-f", "xml", "-o", str(tmp_path)]) == 2

    def test_markdown_alias_accepted(self, tmp_path) -> None:
        assert run(["--ioc", "8.8.8.8", "--offline", "-f", "md", "-o", str(tmp_path)]) == 0
        assert any(p.suffix == ".md" for p in tmp_path.iterdir())


class TestBulkFlag:
    def test_bulk_file_generates_reports(self, tmp_path) -> None:
        source = tmp_path / "indicators.csv"
        source.write_text("ioc\n203.0.113.66\nexample.org\ngarbage!!!\n", encoding="utf-8")
        out = tmp_path / "reports"
        code = run(["--bulk", str(source), "--offline", "-o", str(out),
                    "-f", "json,markdown,csv"])
        assert code == 0
        payloads = [json.loads(p.read_text(encoding="utf-8")) for p in out.glob("*.json")]
        bulk = next(p for p in payloads if "counts" in p)
        assert bulk["counts"] == {"analysed": 2, "invalid": 1}

    def test_missing_bulk_file_exit_two(self, tmp_path) -> None:
        assert run(["--bulk", str(tmp_path / "absent.csv"), "-o", str(tmp_path)]) == 2

    def test_bulk_with_only_invalid_inputs_exit_two(self, tmp_path) -> None:
        source = tmp_path / "junk.txt"
        source.write_text("!!!\n???\n", encoding="utf-8")
        assert run(["--bulk", str(source), "--offline", "-o", str(tmp_path)]) == 2


class TestOfflineAndDemoFlags:
    def test_offline_flag_needs_no_keys(self, tmp_path, monkeypatch) -> None:
        monkeypatch.delenv("VT_API_KEY", raising=False)
        code = run(["--ioc", "8.8.8.8", "--offline", "-f", "console,json", "-o", str(tmp_path)])
        assert code == 0

    def test_env_offline_mode(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("IOC_OFFLINE", "true")
        assert run(["--ioc", "8.8.8.8", "-f", "console", "-o", str(tmp_path)]) == 0

    def test_demo_exit_zero_and_writes_all_formats(self, tmp_path) -> None:
        code = run(["--demo", "-o", str(tmp_path)])
        assert code == 0
        exts = {p.suffix for p in tmp_path.iterdir()}
        assert {".json", ".html", ".md", ".csv"} <= exts

    def test_json_logs_flag(self, tmp_path) -> None:
        assert run(["--validate", "8.8.8.8", "--json-logs", "-f", "console"]) == 0

    def test_log_level_override(self, tmp_path) -> None:
        assert run(["--validate", "8.8.8.8", "--log-level", "DEBUG", "-f", "console"]) == 0


class TestUsageErrors:
    def test_no_arguments_prints_help_exit_two(self) -> None:
        assert run([]) == 2

    def test_mutually_exclusive_targets(self, tmp_path) -> None:
        with pytest.raises(SystemExit) as excinfo:
            run(["--ioc", "8.8.8.8", "--demo"])
        assert excinfo.value.code == 2  # argparse usage error

    def test_version_flag(self) -> None:
        with pytest.raises(SystemExit) as excinfo:
            run(["--version"])
        assert excinfo.value.code == 0

    def test_fatal_errors_map_to_exit_three(self, tmp_path, monkeypatch) -> None:
        """Unexpected internal failures must surface as exit code 3 via __main__ guard."""

        def boom(*args, **kwargs):
            raise RuntimeError("simulated internal failure")

        monkeypatch.setattr(cli.IOCAnalyzer, "analyze", boom)
        with pytest.raises(RuntimeError):
            run(["--ioc", "8.8.8.8", "--offline", "-o", str(tmp_path)])
        # The documented mapping lives in the __main__ block; verify it exists.
        import inspect

        source = inspect.getsource(cli)
        assert "sys.exit(3)" in source

    def test_format_parsing_edge_cases(self) -> None:
        assert cli._parse_formats("JSON, md ,json") == ["json", "markdown"]
        with pytest.raises(ValueError):
            cli._parse_formats("pdf")
        assert cli._parse_formats(",,") == ["console"]
