"""Application configuration and secrets management.

Security notes
--------------
* API keys are **never** hard-coded. They are read from environment
  variables (optionally loaded from a local ``.env`` file for development).
* The ``.env`` file is git-ignored; only ``.env.example`` ships with the
  repository.
* Config objects redact secrets in ``__repr__`` so keys cannot leak into logs,
  tracebacks or REPL output.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ``python-dotenv`` is an optional convenience for local development. The
# application must run correctly without it (production containers inject
# environment variables directly).
try:  # pragma: no cover - trivial import guard
    from dotenv import load_dotenv

    _HAS_DOTENV = True
except ImportError:  # pragma: no cover
    _HAS_DOTENV = False

_ENV_KEY_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _redact(value: Optional[str]) -> str:
    """Return a partially masked representation of a secret."""
    if not value:
        return "<unset>"
    if len(value) <= 4:
        return "****"
    return f"{value[:2]}{'*' * 6}{value[-2:]}"


@dataclass(frozen=True)
class ConnectorSettings:
    """Runtime settings shared by every threat-intelligence connector."""

    timeout_seconds: float = 15.0
    max_retries: int = 3
    backoff_factor: float = 0.7
    user_agent: str = "ioc-intelligence-analyzer/1.0 (+https://github.com)"


@dataclass(frozen=True)
class AppConfig:
    """Immutable application configuration resolved from the environment."""

    vt_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    greynoise_api_key: Optional[str] = None
    connectors: ConnectorSettings = field(default_factory=ConnectorSettings)
    offline_mode: bool = False
    log_level: str = "INFO"
    report_output_dir: Path = Path("reports")

    # ------------------------------------------------------------------ #
    # Construction helpers
    # ------------------------------------------------------------------ #
    @classmethod
    def from_env(cls, env_file: Optional[str | Path] = None) -> "AppConfig":
        """Build configuration strictly from environment variables.

        Args:
            env_file: Optional explicit path to a ``.env`` file. When omitted
                and ``python-dotenv`` is available, a ``./.env`` file (if any)
                is loaded without overriding already-exported variables.

        Returns:
            A frozen :class:`AppConfig` instance. Secrets are never logged.
        """
        if _HAS_DOTENV:
            if env_file is not None:
                load_dotenv(dotenv_path=str(env_file), override=False)
            else:
                load_dotenv(override=False)

        log_level = os.getenv("IOC_LOG_LEVEL", "INFO").upper()
        if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            log_level = "INFO"

        return cls(
            vt_api_key=os.getenv("VT_API_KEY") or None,
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY") or None,
            greynoise_api_key=os.getenv("GREYNOISE_API_KEY") or None,
            connectors=ConnectorSettings(
                timeout_seconds=_float_env("IOC_TIMEOUT_SECONDS", 15.0),
                max_retries=int(_float_env("IOC_MAX_RETRIES", 3.0)),
                backoff_factor=_float_env("IOC_BACKOFF_FACTOR", 0.7),
            ),
            offline_mode=_bool_env("IOC_OFFLINE"),
            log_level=log_level,
            report_output_dir=Path(os.getenv("IOC_REPORT_DIR", "reports")),
        )

    # ------------------------------------------------------------------ #
    # Security hardening
    # ------------------------------------------------------------------ #
    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            "AppConfig("
            f"vt_api_key={_redact(self.vt_api_key)}, "
            f"abuseipdb_api_key={_redact(self.abuseipdb_api_key)}, "
            f"greynoise_api_key={_redact(self.greynoise_api_key)}, "
            f"offline_mode={self.offline_mode}, "
            f"log_level={self.log_level!r}, "
            f"report_output_dir={str(self.report_output_dir)!r})"
        )

    def redacted_dict(self) -> dict[str, object]:
        """Return a JSON-safe, secret-free view of the configuration."""
        return {
            "vt_api_key": _redact(self.vt_api_key),
            "abuseipdb_api_key": _redact(self.abuseipdb_api_key),
            "greynoise_api_key": _redact(self.greynoise_api_key),
            "offline_mode": self.offline_mode,
            "log_level": self.log_level,
            "report_output_dir": str(self.report_output_dir),
            "connector_timeout_seconds": self.connectors.timeout_seconds,
            "connector_max_retries": self.connectors.max_retries,
        }

    def has_any_provider_key(self) -> bool:
        """True when at least one live threat-intelligence provider is usable."""
        return bool(self.vt_api_key or self.abuseipdb_api_key or self.greynoise_api_key)


def validate_env_var_name(name: str) -> bool:
    """Defensive helper used by tooling that writes ``.env`` files."""
    return bool(_ENV_KEY_PATTERN.match(name))


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _bool_env(name: str) -> bool:
    raw = (os.getenv(name) or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}
