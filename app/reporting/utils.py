"""Shared report helpers: filename sanitisation and safe output writing."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from app.core.ioc import ValidatedIOC

_SAFE_TOKEN = re.compile(r"[A-Za-z0-9._\-]{1,64}")


def sanitize_ioc_token(value: str) -> str:
    """Derive a filesystem-safe token from an IOC value.

    Defence against path traversal / separator injection (CWE-22): anything
    that is not ``[A-Za-z0-9._-]`` is replaced with ``_``; every dot run is
    collapsed to a single underscore so relative-path segments (``..``) and
    hidden files can never be produced.
    """
    token = re.sub(r"[^A-Za-z0-9._\-]", "_", value)[:64].strip("._")
    token = re.sub(r"\.+", "_", token)
    return token or "ioc"


def build_filename(ioc: ValidatedIOC, extension: str) -> str:
    """Compose ``ioc_<type>_<token>_<utcstamp>.<ext>``."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"ioc_{ioc.ioc_type.value}_{sanitize_ioc_token(ioc.value)}_{stamp}.{extension}"


def ensure_output_dir(directory: Path) -> Path:
    """Create *directory* if needed and return it (relative paths resolve to CWD)."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def write_text_atomic(path: Path, content: str) -> Path:
    """Write UTF-8 text via temp-file + rename to avoid truncated reports."""
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)
    return path
