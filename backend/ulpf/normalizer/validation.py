"""Validation helpers for ULPF Phase 4 normalizer."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

logger = logging.getLogger("ulpf.normalizer.validation")


def validate_ip(value: Any) -> tuple[str | None, str | None]:
    """Validate an IP address.

    Returns:
        Tuple of (normalized_ip, error). ``normalized_ip`` is ``None`` on failure.
    """
    if value is None:
        return None, None
    try:
        addr = ipaddress.ip_address(str(value).strip())
        return str(addr), None
    except ValueError as exc:
        return None, f"Invalid IP address: {exc}"


def validate_port(value: Any) -> tuple[int | None, str | None]:
    """Validate a network port.

    Returns:
        Tuple of (port, error). ``port`` is ``None`` on failure.
    """
    if value is None:
        return None, None
    try:
        port = int(value)
        if 0 <= port <= 65535:
            return port, None
        return None, f"Port out of range: {port}"
    except (ValueError, TypeError) as exc:
        return None, f"Invalid port: {exc}"


def validate_protocol(value: Any) -> tuple[str | None, str | None]:
    """Normalize and validate a protocol string.

    Returns:
        Tuple of (protocol, error). ``protocol`` is ``None`` on failure.
    """
    if value is None:
        return None, None
    proto = str(value).strip().upper()
    if not proto:
        return None, None
    return proto, None
