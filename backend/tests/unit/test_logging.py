"""Unit tests for the logging helper."""

from __future__ import annotations

import logging

from ulpf.common.logging import configure_root, get_logger


def test_get_logger_returns_named_logger():
    logger = get_logger("ulpf.test.module")
    assert logger.name == "ulpf.test.module"


def test_logger_has_handler_after_configuration():
    configure_root(level=logging.DEBUG)
    root = logging.getLogger()
    assert any(h.level <= logging.DEBUG for h in root.handlers) is True
