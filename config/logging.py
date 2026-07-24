from __future__ import annotations

import logging
import os
from typing import Any

try:
    import structlog
except ImportError:  # pragma: no cover - fallback for minimal environments
    structlog = None


def _get_log_level() -> int:
    """Get log level from environment variable."""
    env_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    return level_map.get(env_level, logging.INFO)


def configure() -> None:
    log_level = _get_log_level()

    if structlog is None:
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        return

    structlog.configure(
        processors=[
            structlog.processors.KeyValueRenderer(key_order=["event", "cve_id"])
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.PrintLoggerFactory(),
    )


def get_logger(name: str | None = None):
    if structlog is None:
        return _FallbackLogger(logging.getLogger(name or "cve-ti-platform"))
    return structlog.get_logger(name)


class _FallbackLogger:
    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def _format(self, message: str, **kwargs: Any) -> str:
        if not kwargs:
            return message
        rendered = " ".join(f"{key}={value}" for key, value in sorted(kwargs.items()))
        return f"{message} {rendered}".strip()

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._logger.debug(self._format(message, **kwargs), *args)

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._logger.info(self._format(message, **kwargs), *args)

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._logger.warning(self._format(message, **kwargs), *args)

    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._logger.error(self._format(message, **kwargs), *args)

    def exception(self, message: str, *args: Any, **kwargs: Any) -> None:
        self._logger.exception(self._format(message, **kwargs), *args)


logger = get_logger(__name__)
