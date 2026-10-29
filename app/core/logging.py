"""Structured logging for the IOC Intelligence Analyzer.

Provides:
* Console logging (human readable) and optional rotating file logging.
* Machine-readable JSON log lines for SIEM ingestion (Splunk/Elastic later).
* Automatic secret redaction so API keys can never leak into logs.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Patterns that look like credentials; values matching these are masked before
# any log record leaves this process.
_REDACT_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Common API-key query params / headers echoed inside messages
    re.compile(r"(?i)\b(key|token|secret|authorization|api[_-]?key)\b\s*[=:]\s*\S+"),
    # VirusTotal-style keys (39 chars ending in '01'/'I0'...) - generic long hex/base64 blobs
    re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"),
)

_REDACTED = "[REDACTED]"


def redact(text: str) -> str:
    """Mask anything that resembles a credential inside *text*.

    The heuristic intentionally over-redacts long opaque tokens: log readability
    matters less than preventing secret leakage into files/SIEM.
    """
    out = text
    out = _REDACT_PATTERNS[0].sub(lambda m: f"{m.group(1)}={_REDACTED}", out)
    out = _REDACT_PATTERNS[1].sub(_REDACTED, out)
    return out


class RedactingFormatter(logging.Formatter):
    """Formatter that scrubs secrets from the formatted message."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: D102
        message = super().format(record)
        return redact(message)


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log line (SIEM friendly, still redacted)."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: D102
        payload = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(str(record.getMessage())),
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=True)


_CONFIGURED = False


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    json_logs: bool = False,
) -> logging.Logger:
    """Configure the root application logger exactly once.

    Args:
        level: One of DEBUG/INFO/WARNING/ERROR/CRITICAL.
        log_file: When provided, adds a rotating file handler (5 MB x 3).
        json_logs: Emit JSON lines instead of human readable text.

    Returns:
        The configured ``ioc_analyzer`` logger.
    """
    global _CONFIGURED
    logger = logging.getLogger("ioc_analyzer")
    if _CONFIGURED:
        return logger

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)
    logger.propagate = False

    handler: logging.Handler
    if json_logs:
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(JsonFormatter())
    else:
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(
            RedactingFormatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
        )
    logger.addHandler(handler)

    if log_file is not None:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        rotating = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        if json_logs:
            rotating.setFormatter(JsonFormatter())
        else:
            rotating.setFormatter(
                RedactingFormatter(
                    "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
                )
            )
        logger.addHandler(rotating)

    _CONFIGURED = True
    return logger


def get_logger(name: str = "ioc_analyzer") -> logging.Logger:
    """Return a child logger under the configured application namespace."""
    if not name.startswith("ioc_analyzer"):
        name = f"ioc_analyzer.{name}"
    return logging.getLogger(name)
