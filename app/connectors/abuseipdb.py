"""AbuseIPDB v2 connector.

Docs: https://www.abuseipdb.com/api (endpoint ``/check``). Auth via the
``Key`` header. The free tier enforces 1 request/second; HTTP 402/429 are
mapped to normalised statuses by the base connector's retry machinery.
"""

from __future__ import annotations

from typing import Any

from app.connectors.base import BaseConnector
from app.core.ioc import IOCType, ValidatedIOC
from app.core.models import EnrichmentResult, ProviderStatus

_API = "https://api.abuseipdb.com/api/v2/check"

#: AbuseIPDB is an IP reputation service - only IP indicators apply.
_SUPPORTED = frozenset({IOCType.IPV4, IOCType.IPV6})

#: Categories that indicate active malicious infrastructure used for scoring
#: hints in the analyst summary (botnets, C2, exploit hosts, malware).
_SEVERE_CATEGORIES = {
    1: "Invalid",
    3: "Web Spam",
    4: "Email Spam",
    5: "Brute Force",
    8: "Botnet",
    9: "Probe / Scanning",
    10: "Denial of Service",
    11: "Exploited Host",
    14: "Open Proxy",
    18: "Malicious Host",
    19: "Torrent / P2P File Sharing",
    20: "Received Malicious Spam",
    21: "SSH",
    22: "IPsec / VPN",
    23: "Tor Node",
}


class AbuseIPDBConnector(BaseConnector):
    """Normalises AbuseIPDB confidence/fraud-score data."""

    name = "abuseipdb"
    display_name = "AbuseIPDB"
    supported_types = _SUPPORTED

    def _lookup(self, ioc: ValidatedIOC) -> EnrichmentResult:
        payload = self._request_json(
            "GET",
            _API,
            headers={
                "Key": self._api_key,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ioc.value,
                # Release-1 default lookback window (days). Tunable later.
                "maxAgeInDays": 90,
            },
        )

        data = payload.get("data")
        if not isinstance(data, dict):
            return EnrichmentResult(
                provider=self.name,
                status=ProviderStatus.NO_DATA,
                summary="No AbuseIPDB record for this address",
            )

        abuse_score = int(data.get("abuseConfidenceScore") or 0)
        total_reports = int(data.get("totalReports") or 0)
        num_distinct = int(data.get("numDistinctReports") or 0)
        categories_raw = data.get("usageCategories") or data.get("blacklistCategories") or []

        categories: list[str] = []
        severe: list[str] = []
        for cat in categories_raw:
            if not isinstance(cat, dict):
                continue
            label = str(cat.get("name") or _SEVERE_CATEGORIES.get(int(cat.get("id", 0) or 0), ""))
            if not label:
                continue
            categories.append(label)
            cat_id = int(cat.get("id", 0) or 0)
            if cat_id in {8, 11, 18}:  # botnet / exploited host / malicious host
                severe.append(label)

        country = data.get("countryCode")
        isp = data.get("isp")
        is_whitelisted = bool(data.get("isWhitelisted"))
        # Tor status arrives either as an explicit flag (enterprise responses)
        # or must be inferred from the reported categories (community v2).
        # Normalise to a *always-present* boolean so downstream consumers never
        # have to guess which shape the provider returned.
        raw_tor = data.get("isTor", data.get("is_tor"))
        if isinstance(raw_tor, bool):
            is_tor = raw_tor
        else:
            is_tor = any("tor" in c.lower() for c in categories)

        confidence = max(0, min(100, abuse_score))
        malicious: Any = None
        if is_whitelisted:
            malicious = False
        elif abuse_score >= 50 or total_reports > 0:
            malicious = abuse_score >= 25 and total_reports >= 1

        summary_bits = [f"Abuse confidence {abuse_score}% from {total_reports} reports"]
        if num_distinct:
            summary_bits.append(f"{num_distinct} distinct reporters")
        if categories:
            summary_bits.append("categories: " + ", ".join(categories[:6]))
        if is_tor:
            summary_bits.append("Tor exit node")

        details = {
            "abuse_confidence_score": abuse_score,
            "total_reports": total_reports,
            "distinct_reports": num_distinct,
            "report_categories": categories,
            "severe_categories": severe,
            "country": country,
            "isp": isp,
            "domain": data.get("domain"),
            "is_whitelisted": is_whitelisted,
            "is_tor": is_tor,
            "last_reported": data.get("lastReportedAt"),
        }

        return EnrichmentResult(
            provider=self.name,
            status=ProviderStatus.OK,
            confidence=confidence,
            malicious=malicious,
            summary="; ".join(summary_bits),
            details={k: v for k, v in details.items() if v not in (None, "", [], False)},
            raw_ref=f"https://www.abuseipdb.com/check/{ioc.value}",
        )
