"""
Logging setup for SecureNet Lab.

Every module calls get_logger(__name__) and gets a logger that writes to
stderr and (optionally) a rotating file under logs/. Format comes from
settings.log_format: "json" for machines, "text" for humans.

Usage:
    from src.logging_setup import get_logger

    log = get_logger(__name__)
    log.info("collector started", extra={"component": "collector"})
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from datetime import datetime, timezone

from src.config import settings


_configured = False


class _JsonFormatter(logging.Formatter):
    """One JSON object per line; easy to ship into any log stack later."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging() -> None:
    """Set up root handlers once. Safe to call from multiple modules."""
    global _configured
    if _configured:
        return
    _configured = True

    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)

    if settings.log_format == "json":
        formatter: logging.Formatter = _JsonFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
        )

    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(formatter)
    root.addHandler(stream)

    if settings.log_file_enabled:
        settings.logs_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            settings.logs_dir / "securenet.log",
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger. Call this from every module."""
    configure_logging()
    return logging.getLogger(name)
