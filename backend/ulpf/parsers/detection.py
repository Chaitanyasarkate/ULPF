"""Format and source detection for ULPF Phase 3."""

from __future__ import annotations

import json
import logging
import re

from ulpf.common.models import SourceType

logger = logging.getLogger("ulpf.parsers.detection")

_JSON_INDICATORS = ("{", "[")
_CEF_PREFIX = "CEF:"
_SYSLOG_PATTERN = re.compile(
    r"^(?:<\d+>)?"
    r"[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"
)


def detect_format(payload: str, explicit_format: str = "") -> str:
    """Detect the log format of a payload.

    Detection order:
    1. Use explicit format metadata if provided and non-empty.
    2. Try CEF detection (payload starts with ``CEF:``).
    3. Try JSON detection (starts with ``{`` or ``[``).
    4. Fall back to ``syslog`` if it matches a basic syslog pattern.
    5. Otherwise return ``unknown``.

    Args:
        payload: Raw log payload.
        explicit_format: Format metadata from the raw event, if available.

    Returns:
        One of ``syslog``, ``json``, ``cef``, or ``unknown``.
    """
    if explicit_format:
        fmt = explicit_format.lower()
        if fmt in ("syslog", "json", "cef"):
            return fmt

    stripped = payload.strip()
    if stripped.upper().startswith(_CEF_PREFIX):
        return "cef"

    if stripped.startswith(_JSON_INDICATORS):
        try:
            json.loads(stripped)
            return "json"
        except json.JSONDecodeError:
            pass

    if _SYSLOG_PATTERN.match(stripped):
        return "syslog"

    return "unknown"


def detect_source_type(explicit_source_type: str = "", payload: str = "") -> str:
    """Return the source type, preferring explicit metadata.

    Args:
        explicit_source_type: Source type metadata from the raw event.
        payload: Raw payload for future heuristic detection.

    Returns:
        A source type string, defaulting to ``unknown``.
    """
    if explicit_source_type:
        return explicit_source_type.lower()
    return SourceType.UNKNOWN.value
