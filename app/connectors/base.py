"""Abstract connector layer (SOLID: Dependency Inversion + Open/Closed).

Every threat-intelligence provider implements :class:`BaseConnector`. The base
class centralises the cross-cutting concerns required by the security
requirements: timeouts, bounded retries with exponential backoff and jitter,
rate-limit handling, TLS verification, secret masking and normalised error
mapping. Concrete connectors therefore only translate provider payloads into
:class:`~app.core.models.EnrichmentResult` objects.
"""

from __future__ import annotations

import random
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter

from app.core.config import ConnectorSettings
from app.core.ioc import IOCType, ValidatedIOC
from app.core.logging import get_logger
from app.core.models import EnrichmentResult, ProviderStatus


class ConnectorError(Exception):
    """Raised internally for unrecoverable connector failures."""

    def __init__(self, message: str, status: ProviderStatus = ProviderStatus.PROVIDER_ERROR):
        super().__init__(message)
        self.status = status


class BaseConnector(ABC):
    """Provider-agnostic HTTP connector with retry/timeout/rate-limit safety."""

    #: Machine name used in reports (override in subclasses).
    name: str = "base"
    #: Human name shown in report tables (override in subclasses).
    display_name: str = "Base connector"
    #: IOC types this connector can enrich (empty set = none).
    supported_types: frozenset[IOCType] = frozenset()

    _RETRYABLE_STATUS = {429, 500, 502, 503, 504}

    def __init__(
        self,
        api_key: Optional[str],
        settings: Optional[ConnectorSettings] = None,
        session: Optional[requests.Session] = None,
    ) -> None:
        self._api_key = api_key or ""
        self.settings = settings or ConnectorSettings()
        self._session = session or self._build_session()
        self._log = get_logger(f"connectors.{self.name}")

    # ------------------------------------------------------------------ #
    # Session / transport hardening
    # ------------------------------------------------------------------ #
    def _build_session(self) -> requests.Session:
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=4, pool_maxsize=8)
        session.mount("https://", adapter)
        session.headers.update({"User-Agent": self.settings.user_agent})
        # NOTE: ``verify`` is intentionally left at the secure default (True).
        return session

    @property
    def configured(self) -> bool:
        """Whether this connector has the credentials it needs."""
        return bool(self._api_key)

    # ------------------------------------------------------------------ #
    # Public API used by the orchestration service
    # ------------------------------------------------------------------ #
    def enrich(self, ioc: ValidatedIOC) -> EnrichmentResult:
        """Entry point: skip unconfigured/inapplicable IOCs, else call lookup.

        Never raises - all failures are converted to normalised
        :class:`EnrichmentResult` values so one bad provider cannot break an
        analysis run (availability-first design).
        """
        if ioc.ioc_type not in self.supported_types:
            return EnrichmentResult.skipped(
                self.name, f"{self.display_name} does not support '{ioc.ioc_type.value}' indicators"
            )
        if not self.configured:
            return EnrichmentResult.failure(
                self.name,
                ProviderStatus.CONFIGURATION_ERROR,
                f"No API key configured for {self.display_name} "
                "(set the corresponding environment variable; see .env.example)",
            )
        try:
            return self._lookup(ioc)
        except ConnectorError as exc:
            return EnrichmentResult.failure(self.name, exc.status, str(exc))
        except Exception as exc:  # noqa: BLE001 - deliberate boundary catch
            # Do not include exception args verbatim: they may echo request URLs.
            self._log.warning("%s unexpected failure: %s", self.name, type(exc).__name__)
            return EnrichmentResult.failure(
                self.name, ProviderStatus.PROVIDER_ERROR, "Unexpected connector failure"
            )

    # ------------------------------------------------------------------ #
    # HTTP helpers shared by concrete connectors
    # ------------------------------------------------------------------ #
    def _request_json(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Perform a hardened GET/POST returning parsed JSON.

        Raises:
            ConnectorError: mapped to a normalised :class:`ProviderStatus`.
        """
        last_error: Optional[ConnectorError] = None
        attempts = max(1, int(self.settings.max_retries))

        for attempt in range(1, attempts + 1):
            try:
                response = self._session.request(
                    method=method.upper(),
                    url=url,
                    headers=headers or {},
                    params=params,
                    timeout=self.settings.timeout_seconds,
                )
            except requests.exceptions.Timeout as exc:
                last_error = ConnectorError(
                    f"Request timed out after {self.settings.timeout_seconds}s",
                    ProviderStatus.TIMEOUT,
                )
                self._log.debug("%s timeout (attempt %d/%d): %s", self.name, attempt, attempts, exc.__class__.__name__)
            except requests.exceptions.RequestException as exc:
                # Connection errors are rarely idempotent-safe to repeat many
                # times; still bounded by ``attempts``.
                last_error = ConnectorError(
                    "Network error contacting provider", ProviderStatus.NETWORK_ERROR
                )
                self._log.debug("%s network error (attempt %d/%d): %s", self.name, attempt, attempts, exc.__class__.__name__)
            else:
                handled = self._handle_response(response)
                if handled is not None:
                    return handled
                # 429/5xx fall through to retry/backoff below.
                last_error = ConnectorError(
                    f"Provider returned HTTP {response.status_code}",
                    ProviderStatus.RATE_LIMITED if response.status_code == 429 else ProviderStatus.PROVIDER_ERROR,
                )

            if attempt < attempts:
                delay = self.settings.backoff_factor * (2 ** (attempt - 1))
                # Jitter avoids synchronised retry storms across bulk runs.
                delay += random.uniform(0, 0.25)
                self._log.info("%s retrying in %.2fs (attempt %d/%d)", self.name, delay, attempt, attempts)
                time.sleep(delay)

        assert last_error is not None
        raise last_error

    def _handle_response(self, response: requests.Response) -> Optional[dict[str, Any]]:
        """Translate an HTTP response into JSON payload, ``None`` or raise.

        Returns the parsed body on success, ``None`` when the caller should
        retry (429/5xx), and raises :class:`ConnectorError` for terminal
        conditions (401/403/other 4xx).
        """
        code = response.status_code
        if code in (200, 201):
            try:
                payload = response.json()
            except ValueError as exc:
                raise ConnectorError("Malformed JSON from provider", ProviderStatus.PARSE_ERROR) from exc
            if not isinstance(payload, dict):
                raise ConnectorError("Unexpected provider payload shape", ProviderStatus.PARSE_ERROR)
            return payload
        if code in (401, 403):
            raise ConnectorError(
                "Authentication failed - verify the API key", ProviderStatus.AUTHENTICATION_ERROR
            )
        if code == 404:
            # Providers use 404 for "indicator not seen"; that is data, not error.
            return {"__not_found__": True}
        if code in self._RETRYABLE_STATUS:
            return None
        raise ConnectorError(f"Provider error (HTTP {code})", ProviderStatus.PROVIDER_ERROR)

    # ------------------------------------------------------------------ #
    # Subclass contract
    # ------------------------------------------------------------------ #
    @abstractmethod
    def _lookup(self, ioc: ValidatedIOC) -> EnrichmentResult:
        """Fetch and normalise provider intelligence for a validated IOC."""
        raise NotImplementedError

    # ------------------------------------------------------------------ #
    # Provider-consistency normalisation (no network I/O)
    # ------------------------------------------------------------------ #
    def normalise_offline(self, ioc: ValidatedIOC, reason: Optional[str] = None) -> EnrichmentResult:
        """Return this provider's *data-shaped* row for a no-lookup path.

        Used by the analyzer whenever a lookup cannot or must not hit the
        network (private-address privacy gate, offline mode, or the
        provider-completeness pass filling in an IP-reputation provider that
        was never wired up). Every provider always contributes one row with
        identical structure across all paths; only ``status``/``summary``
        differ. AbuseIPDB/GreyNoise have no Release-1 coverage for non-IP
        types, so those rows are reported as NO_DATA rather than errors —
        "provider has nothing to say" is data, not failure.
        """
        if ioc.ioc_type not in self.supported_types:
            return EnrichmentResult(
                provider=self.name,
                status=ProviderStatus.NO_DATA,
                summary=(
                    f"{self.display_name} has no reputation record for "
                    f"'{ioc.ioc_type.value}' indicators"
                ),
            )
        if reason is None:
            reason = f"{self.display_name} lookup not attempted for this indicator"
        return EnrichmentResult.skipped(self.name, reason)


