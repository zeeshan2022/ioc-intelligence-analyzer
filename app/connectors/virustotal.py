"""VirusTotal v3 connector.

Docs: https://docs.virustotal.com/reference/overview
Auth: ``x-apikey`` header. Free tier: 4 requests/min, 500/day - the base
connector's retry/backoff handles HTTP 429 rate limiting transparently.
"""

from __future__ import annotations

from typing import Any

from app.connectors.base import BaseConnector
from app.core.ioc import IOCType, ValidatedIOC
from app.core.models import EnrichmentResult, ProviderStatus

_BASE = "https://www.virustotal.com/api/v3"

#: IOC types VirusTotal can look up directly in Release 1.
_VT_TYPES = frozenset(
    {IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL, IOCType.MD5, IOCType.SHA1, IOCType.SHA256}
)


class VirusTotalConnector(BaseConnector):
    """Normalises VT ``stats`` (malicious/harmless/suspicious) verdicts."""

    name = "virustotal"
    display_name = "VirusTotal"
    supported_types = _VT_TYPES

    # ------------------------------------------------------------------ #
    def _endpoint_for(self, ioc: ValidatedIOC) -> str:
        value = ioc.value
        if ioc.ioc_type == IOCType.URL:
            # VT3 expects a base64(url) id in the URL path; keep padding safe.
            import base64

            url_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
            return f"{_BASE}/urls/{url_id}"
        if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            return f"{_BASE}/ip_addresses/{value}"
        if ioc.ioc_type == IOCType.DOMAIN:
            return f"{_BASE}/domains/{value}"
        return f"{_BASE}/files/{value}"

    def _lookup(self, ioc: ValidatedIOC) -> EnrichmentResult:
        payload = self._request_json(
            "GET",
            self._endpoint_for(ioc),
            headers={"x-apikey": self._api_key},
        )
        if payload.get("__not_found__"):
            return EnrichmentResult(
                provider=self.name,
                status=ProviderStatus.NO_DATA,
                summary="Indicator not found in VirusTotal",
            )

        data = payload.get("data") or {}
        attributes = data.get("attributes") or {}
        stats_raw = attributes.get("last_analysis_stats") or {}
        stats = {k: int(v) for k, v in stats_raw.items() if isinstance(v, (int, float))}

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total_engines = sum(stats.values()) or 0

        confidence = self._confidence(malicious, suspicious, total_engines)
        verdict: Any = None
        if total_engines:
            verdict = malicious > 0 or suspicious >= max(2, total_engines * 0.2)

        summary_bits = [f"{malicious}/{total_engines} engines flagged as malicious"]
        if suspicious:
            summary_bits.append(f"{suspicious} suspicious")
        names = self._top_malicious_names(attributes)
        if names:
            summary_bits.append("labels: " + ", ".join(names[:5]))

        details: dict[str, Any] = {
            "analysis_stats": stats,
            "malicious_detectors": names,
            "source": attributes.get("source"),
            "type": attributes.get("type"),
            "first_seen": attributes.get("first_submission_date"),
            "last_seen": attributes.get("last_analysis_date"),
            "reputation": attributes.get("reputation"),
            "as_owner": attributes.get("as_owner"),
            "country": attributes.get("country"),
        }
        relationships = (data.get("relationships") or {}).get("belongs_to_cluster") or {}
        cluster = ((relationships.get("data") or [{}])[0] or {}).get("id")
        if cluster:
            details["threat_cluster"] = cluster

        return EnrichmentResult(
            provider=self.name,
            status=ProviderStatus.OK,
            confidence=confidence,
            malicious=bool(verdict) if verdict is not None else None,
            summary="; ".join(summary_bits),
            details={k: v for k, v in details.items() if v not in (None, "", [], {})},
            raw_ref=data.get("links", {}).get("self") or f"https://www.virustotal.com/gui/",
        )

    # ------------------------------------------------------------------ #
    @staticmethod
    def _confidence(malicious: int, suspicious: int, total: int) -> int:
        """Map engine detection counts onto a 0-100 confidence figure."""
        if total <= 0:
            return 0
        ratio = (malicious + suspicious * 0.5) / total
        score = int(ratio * 100)
        if malicious and score < 10:
            score = 10
        return max(0, min(100, score))

    @staticmethod
    def _top_malicious_names(attributes: dict[str, Any]) -> list[str]:
        analyses = attributes.get("last_analysis_results") or {}
        names: list[str] = []
        if isinstance(analyses, dict):
            for engine, result in analyses.items():
                if isinstance(result, dict) and str(result.get("category", "")).lower() == "malicious":
                    label = str(result.get("result") or engine)
                    if label not in names:
                        names.append(label)
        return names[:20]
