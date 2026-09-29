"""
Structured logging helper for ULPF.

Provides a single ``get_logger`` entry point that every module can use so that
log format and level are consistent. Uses stdlib ``logging`` only (no extra
dependencies) to keep the air-gapped footprint small.
"""

from __future__ import annotations

import logging
import os
import sys


def _default_level() -> int:
    level = os.environ.get("ULPF_LOG_LEVEL", "INFO").upper()
    return getattr(logging, level, logging.INFO)


def configure_root(level: int | None = None) -> None:
    level = level if level is not None else _default_level()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)sZ %(levelname)-7s %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    root = logging.getLogger()
    # Avoid duplicate handlers when called more than once (e.g. in tests).
    if not root.handlers:
        root.addHandler(handler)
    root.setLevel(level)


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger. Ensures the root is configured on first use."""
    if not logging.getLogger().handlers:
        configure_root()
    return logging.getLogger(name)
