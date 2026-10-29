"""Shared pytest fixtures and security guardrails for the test suite."""

from __future__ import annotations

import socket
from typing import Any, Optional

import pytest
import requests

from app.core.config import AppConfig, ConnectorSettings
from app.core.ioc import IOCType, ValidatedIOC
from app.core.models import EnrichmentResult, ProviderStatus


# --------------------------------------------------------------------------- #
# Hermetic guarantee: block every outbound socket once a test starts.
# --------------------------------------------------------------------------- #
class _NetworkBlocked(RuntimeError):
    """Raised when a test attempts real network I/O."""


_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _guarded_create_connection(address: Any, *args: Any, **kwargs: Any) -> socket.socket:
    host = address[0] if isinstance(address, tuple) else address
    if host not in _ALLOWED_HOSTS:
        raise _NetworkBlocked(f"Outbound network access blocked in tests: {host!r}")
    return _original_create_connection(address, *args, **kwargs)  # type: ignore[attr-defined]


_original_create_connection = socket.create_connection
socket.create_connection = _guarded_create_connection  # type: ignore[assignment]


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Autouse fixture ensuring no test reaches the internet."""

    def _blocked_connect(self: Any, *args: Any, **kwargs: Any) -> None:  # pragma: no cover
        raise _NetworkBlocked("urllib3 connect attempted during test")

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", _blocked_connect, raising=True)


# --------------------------------------------------------------------------- #
# Environment isolation
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove provider credentials from the environment for deterministic runs."""
    for var in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY", "IOC_OFFLINE"):
        monkeypatch.delenv(var, raising=False)


# --------------------------------------------------------------------------- #
# Builders / factories
# --------------------------------------------------------------------------- #


@pytest.fixture()
def fast_settings() -> ConnectorSettings:
    """Connector settings with near-zero delays so retry tests stay fast."""
    return ConnectorSettings(timeout_seconds=1.0, max_retries=3, backoff_factor=0.0)


@pytest.fixture()
def offline_config(tmp_path) -> AppConfig:
    """Configuration with no provider keys and offline mode disabled by default.

    ``report_output_dir`` points at a per-test tmp_path so reports never touch
    the repository working tree.
    """
    return AppConfig(offline_mode=False, report_output_dir=tmp_path / "reports")


# --------------------------------------------------------------------------- #
# Mock HTTP transport used by connector tests (never hits the network)
# --------------------------------------------------------------------------- #


class FakeResponse:
    """Minimal stand-in for :class:`requests.Response`."""

    def __init__(
        self,
        status_code: int = 200,
        json_payload: Optional[dict] = None,
        raise_json_error: bool = False,
    ) -> None:
        self.status_code = status_code
        self._json_payload = json_payload if json_payload is not None else {}
        self._raise_json_error = raise_json_error

    def json(self) -> dict:
        if self._raise_json_error:
            raise ValueError("no json")
        return self._json_payload


class FakeSession:
    """Scriptable session double: pops one canned response per request call.

    Records every call so tests can assert on retry counts, headers and params.
    Exceptions listed in ``raises`` are thrown instead of returning responses.
    """

    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[dict] = []

    def request(self, method: str, url: str, headers: Optional[dict] = None,
                params: Optional[dict] = None, timeout: Optional[float] = None) -> FakeResponse:
        self.calls.append({"method": method, "url": url, "headers": dict(headers or {}),
                           "params": dict(params or {}), "timeout": timeout})
        if not self.responses:
            raise AssertionError("FakeSession ran out of scripted responses")
        outcome = self.responses.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def make_ioc(value: str, ioc_type: IOCType = IOCType.IPV4,
             metadata: Optional[dict] = None) -> ValidatedIOC:
    """Build a ValidatedIOC directly (bypasses re-validation; test helper)."""
    return ValidatedIOC(value=value, ioc_type=ioc_type, valid=True,
                        reason="", metadata=metadata or {})


def ok_result(provider: str, *, confidence: int = 0, malicious: Optional[bool] = None,
              summary: str = "", details: Optional[dict] = None) -> EnrichmentResult:
    """Construct an OK EnrichmentResult for scoring/summary tests."""
    return EnrichmentResult(
        provider=provider,
        status=ProviderStatus.OK,
        confidence=confidence,
        malicious=malicious,
        summary=summary,
        details=details or {},
    )
