"""Analysis orchestration service.

Wires the pipeline: validate -> enrich (connectors) -> score -> MITRE map ->
summarise. The analyzer accepts an injected list of connectors so the CLI,
tests (with mocks) and the future FastAPI app all share one code path
(Dependency Injection; no hidden global state).
"""

from __future__ import annotations

import csv
import io
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Iterable, Optional

from app.connectors.abuseipdb import AbuseIPDBConnector
from app.connectors.greynoise import GreyNoiseConnector
from app.connectors.virustotal import VirusTotalConnector
from app.core.config import AppConfig
from app.core.ioc import ValidatedIOC, extract_network_target, validate_ioc, validate_many
from app.core.logging import get_logger
from app.core.models import (
    AnalysisResult,
    BulkAnalysisReport,
    EnrichmentResult,
    ProviderStatus,
)
from app.services.scoring import score_enrichments
from app.services.summary import build_summary


class IOCAnalyzer:
    """Facade used by every delivery layer (CLI now, API/dashboard later)."""

    def __init__(self, config: AppConfig, connectors: Optional[list] = None) -> None:
        self.config = config
        self._log = get_logger("services.analyzer")
        if connectors is not None:
            self.connectors = connectors
        else:
            self.connectors = self._default_connectors(config)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _default_connectors(config: AppConfig) -> list:
        settings = config.connectors
        return [
            VirusTotalConnector(config.vt_api_key, settings),
            AbuseIPDBConnector(config.abuseipdb_api_key, settings),
            GreyNoiseConnector(config.greynoise_api_key, settings),
        ]

    # ------------------------------------------------------------------ #
    def analyze(self, raw_value: str) -> Optional[AnalysisResult]:
        """Run the full pipeline for a single indicator string.

        Returns ``None`` when validation fails (caller reports the reason via
        :meth:`analyze_bulk` / CLI output which includes invalid inputs).
        """
        validated = validate_ioc(raw_value)
        if not validated.valid:
            self._log.warning("Rejected invalid indicator input: %s", validated.reason)
            return None
        return self.analyze_validated(validated)

    def analyze_validated(self, ioc: ValidatedIOC) -> AnalysisResult:
        """Enrich + score + narrate an already-validated indicator."""
        enrichments = self._enrich(ioc)
        risk = score_enrichments(ioc.value, ioc.ioc_type.value, enrichments)
        summary = build_summary(ioc, risk, enrichments)
        self._log.info(
            "Completed analysis for %s (%s): score=%d level=%s",
            ioc.value,
            ioc.ioc_type.value,
            risk.score,
            risk.level.value,
        )
        return AnalysisResult(ioc=ioc, risk=risk, enrichments=enrichments, summary=summary)

    def analyze_bulk(self, values: Iterable[str]) -> BulkAnalysisReport:
        """Validate a batch, analyse every valid unique IOC, keep rejects."""
        valid, invalid = validate_many(values)
        report = BulkAnalysisReport(invalid_inputs=invalid)
        for ioc in valid:
            report.results.append(self.analyze_validated(ioc))
        return report

    def analyze_file(self, path: Path) -> BulkAnalysisReport:
        """Read indicators from a text or CSV file (one column or one per line)."""
        return self.analyze_bulk(read_indicator_file(path))

    # ------------------------------------------------------------------ #
    def _enrich(self, ioc: ValidatedIOC) -> list[EnrichmentResult]:
        """Fan out to connectors concurrently; preserve deterministic order.

        Provider consistency contract: every connector wired into the run
        always contributes exactly one normalised ``EnrichmentResult`` row,
        regardless of path (private IP, offline mode, missing API key,
        unsupported IOC type, transport failure). Rows therefore carry the
        same structure across *all* analyzer paths — status differs, shape
        never does.

        Private-range IPs are never sent to external providers (privacy
        control - internal addresses must not leak to third parties); their
        rows take the normal per-connector skip path so each provider reports
        its own status.
        """
        if self._is_internal(ioc):
            target = extract_network_target(ioc) or ioc.value
            reason = (
                f"{target} is a private address - lookup withheld to prevent "
                "leaking internal infrastructure to third-party providers."
            )
            self._log.info("Privacy gate engaged for %s", target)
            return [
                EnrichmentResult.skipped(connector.name, reason)
                for connector in self.connectors
            ]

        if self.config.offline_mode:
            return [
                EnrichmentResult.skipped(c.name, "Offline mode enabled (IOC_OFFLINE=true)")
                for c in self.connectors
            ]

        workers = max(1, min(3, len(self.connectors)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="enrich") as pool:
            futures = [pool.submit(connector.enrich, ioc) for connector in self.connectors]
            results: list[EnrichmentResult] = []
            for connector, future in zip(self.connectors, futures):
                try:
                    results.append(future.result())
                except Exception:  # noqa: BLE001 - boundary; enrich() should not raise
                    self._log.error("Connector %s crashed unexpectedly", connector.name)
                    results.append(
                        EnrichmentResult.failure(
                            connector.name,
                            ProviderStatus.PROVIDER_ERROR,
                            "Connector crashed",
                        )
                    )

        # IOC-type applicability must never depend on the default connector
        # set: if an IP-reputation provider (AbuseIPDB / GreyNoise) was not
        # wired up at all for an IP indicator, surface it as an explicit
        # SKIPPED row so analysts can distinguish "provider does not handle
        # this type" from "provider failed". This keeps the provider set
        # {virustotal, abuseipdb, greynoise} consistent across every path.
        declared = {c.name for c in self.connectors}
        for name, display in (("abuseipdb", "AbuseIPDB"), ("greynoise", "GreyNoise")):
            if name not in declared and ioc.ioc_type.value in {"ipv4", "ipv6"}:
                results.append(
                    EnrichmentResult.skipped(name, f"{display} connector not configured for this run")
                )
        return results

    @staticmethod
    def _is_internal(ioc: ValidatedIOC) -> bool:
        """Privacy gate: only *truly internal* addresses are withheld.

        RFC1918, loopback and link-local ranges must never leave the building.
        Documentation / TEST-NET ranges (e.g. ``203.0.113.0/24``) are flagged
        ``is_reserved`` by :mod:`ipaddress` but are standard *public* test
        blocks that providers happily answer for; short-circuiting them here
        would make reserved-IP paths return a different provider structure
        than normal public paths. Analysts can still force local-only runs via
        ``--offline`` / ``IOC_OFFLINE=true``, which skips every provider.
        """
        meta = ioc.metadata or {}
        if ioc.ioc_type.value in {"ipv4", "ipv6"}:
            return bool(meta.get("is_private") or meta.get("is_loopback") or meta.get("is_link_local"))
        return False


# --------------------------------------------------------------------------- #
# File input helper (shared by CLI --bulk and tests)
# --------------------------------------------------------------------------- #


def read_indicator_file(path: Path) -> list[str]:
    """Parse newline-delimited or single-column CSV files of indicators.

    Accepts optional header rows named ``ioc``, ``indicator``, ``value`` or
    ``ioc_value``. Lines starting with ``#`` are treated as comments. Blank
    lines are ignored. Malformed CSV rows degrade gracefully to whitespace
    splitting so hand-maintained lists still work.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Indicator file not found: {path}")

    text = path.read_text(encoding="utf-8", errors="replace")
    values: list[str] = []

    stripped = text.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        # JSON array support for feed interoperability.
        import json

        data = json.loads(stripped)
        if isinstance(data, list):
            return [str(item) for item in data if str(item).strip()]

    looks_csv = "," in text.splitlines()[0] if text.splitlines() else False
    # Header tokens recognised on the first column of BOTH CSV and plain
    # single-column files. One shared set guarantees a header row is skipped
    # identically regardless of whether the file "looks like" CSV — otherwise
    # a header such as ``ioc`` in a one-column file is mistaken for an
    # indicator and inflates the invalid count reported by --bulk runs.
    header_tokens = {"ioc", "indicator", "value", "ioc_value", "type,value"}
    if looks_csv:
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            if not row:
                continue
            cell = row[0].strip()
            if cell.lower() in header_tokens:
                continue
            if cell.startswith("#"):
                continue
            if cell:
                values.append(cell)
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower() in header_tokens:
                continue
            values.append(line.split(",")[0].strip())
    return values
