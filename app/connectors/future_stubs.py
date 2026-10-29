"""Future connector stubs (Release 2+).

These classes document the integration surface for AlienVault OTX, URLHaus,
Shodan, Whois and DNS. They implement the same :class:`BaseConnector` contract
so wiring them into the orchestration service later is a one-line change in
``app/services/enrichment.py`` - no refactoring required.
"""

from __future__ import annotations

from app.connectors.base import BaseConnector
from app.core.ioc import IOCType, ValidatedIOC
from app.core.models import EnrichmentResult, ProviderStatus


class _PlannedConnector(BaseConnector):
    """Shared placeholder behaviour for not-yet-implemented providers."""

    planned_release = "2.x"

    def _lookup(self, ioc: ValidatedIOC) -> EnrichmentResult:  # pragma: no cover
        return EnrichmentResult(
            provider=self.name,
            status=ProviderStatus.SKIPPED,
            summary=(
                f"{self.display_name} integration is planned for "
                f"release {self.planned_release}; see docs/ROADMAP.md"
            ),
        )


class AlienVaultOTXConnector(_PlannedConnector):
    name = "alienvault_otx"
    display_name = "AlienVault OTX"
    supported_types = frozenset({IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL})
    planned_release = "2.0"


class URLHausConnector(_PlannedConnector):
    name = "urlhaus"
    display_name = "URLHaus (abuse.ch)"
    supported_types = frozenset({IOCType.IPV4, IOCType.DOMAIN, IOCType.URL})
    planned_release = "2.0"


class ShodanConnector(_PlannedConnector):
    name = "shodan"
    display_name = "Shodan"
    supported_types = frozenset({IOCType.IPV4, IOCType.IPV6})
    planned_release = "2.1"


class WhoisConnector(_PlannedConnector):
    name = "whois"
    display_name = "WHOIS Lookup"
    supported_types = frozenset({IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6})
    planned_release = "2.1"


class DNSConnector(_PlannedConnector):
    name = "dns"
    display_name = "DNS Resolution"
    supported_types = frozenset({IOCType.DOMAIN})
    planned_release = "2.1"
