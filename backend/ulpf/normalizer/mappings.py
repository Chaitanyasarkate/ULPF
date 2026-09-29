"""Field mappings and normalization helpers for ULPF Phase 4."""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("ulpf.normalizer.mappings")

# ---------------------------------------------------------------------------
# Action normalization
# ---------------------------------------------------------------------------

_ACTION_MAP: dict[str, str] = {
    "allow": "allow",
    "accept": "allow",
    "permitted": "allow",
    "permit": "allow",
    "pass": "allow",
    "deny": "deny",
    "drop": "deny",
    "blocked": "deny",
    "block": "deny",
    "reject": "deny",
    "denied": "deny",
    "detected": "detect",
    "detect": "detect",
    "alerted": "detect",
    "alert": "detect",
    "identified": "detect",
}

_COMMON_ACTIONS = {"allow", "deny", "detect", "unknown"}


def normalize_action(raw_action: str | None) -> str:
    """Map a source-specific action string to a common normalized action.

    Args:
        raw_action: Source-specific action value (e.g. ``ALLOW``, ``permitted``).

    Returns:
        One of ``allow``, ``deny``, ``detect``, or ``unknown``.
    """
    if not raw_action:
        return "unknown"
    value = str(raw_action).strip().lower()
    return _ACTION_MAP.get(value, "unknown")


# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[int, str] = {
    0: "low",
    1: "low",
    2: "low",
    3: "medium",
    4: "medium",
    5: "medium",
    6: "high",
    7: "high",
    8: "critical",
    9: "critical",
    10: "critical",
}

_COMMON_SEVERITIES = {"low", "medium", "high", "critical", "unknown"}


def normalize_severity(raw_severity: Any) -> str:
    """Normalize severity to a common string representation.

    Handles numeric severities (syslog 0-7, CEF 0-10) and string values.

    Args:
        raw_severity: Raw severity value from the parser.

    Returns:
        One of ``low``, ``medium``, ``high``, ``critical``, or ``unknown``.
    """
    if raw_severity is None:
        return "unknown"
    try:
        value = int(raw_severity)
        return _SEVERITY_MAP.get(value, "unknown")
    except (ValueError, TypeError):
        str_value = str(raw_severity).strip().lower()
        if str_value in _COMMON_SEVERITIES:
            return str_value
        return "unknown"


# ---------------------------------------------------------------------------
# Timestamp normalization
# ---------------------------------------------------------------------------

_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _normalize_syslog_timestamp(ts_str: str) -> str | None:
    now = datetime.now(timezone.utc)
    m = _SYSLOG_TS.match(ts_str)
    if not m:
        return None
    month_str, day, hour, minute, second = m.groups()
    try:
        month = _MONTH_MAP.get(month_str)
        if month is None:
            return None
        day_int = int(day)
        parsed = datetime(
            now.year,
            month,
            day_int,
            int(hour),
            int(minute),
            int(second),
            tzinfo=timezone.utc,
        )
        if parsed > now:
            parsed = parsed.replace(year=now.year - 1)
        return parsed.isoformat()
    except (ValueError, TypeError):
        return None


def normalize_timestamp(raw_timestamp: str | None) -> str | None:
    """Normalize a timestamp string to ISO-8601 UTC.

    Handles syslog timestamps (``Mon DD HH:MM:SS``) and ISO-8601 strings.

    Args:
        raw_timestamp: Raw timestamp string.

    Returns:
        ISO-8601 UTC timestamp string, or ``None`` if unparseable.
    """
    if not raw_timestamp:
        return None
    ts = str(raw_timestamp).strip()
    if not ts:
        return None

    # Already ISO-8601-ish
    if "T" in ts:
        return ts

    # Syslog-style
    result = _normalize_syslog_timestamp(ts)
    if result:
        return result

    return None


# ---------------------------------------------------------------------------
# Network field validation
# ---------------------------------------------------------------------------


def validate_ip(value: Any) -> tuple[str | None, str | None]:
    """Validate an IP address.

    Returns:
        Tuple of (normalized_ip, error). ``normalized_ip`` is ``None`` on failure.
    """
    if value is None:
        return None, "IP address is None"
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
