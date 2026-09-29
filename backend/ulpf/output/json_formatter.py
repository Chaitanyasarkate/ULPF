"""JSON output formatter for ULPF Phase 9A."""

from __future__ import annotations

import json
import math
from typing import TYPE_CHECKING, Any

from ulpf.output.base import BaseFormatter, OutputFormat

if TYPE_CHECKING:
    from ulpf.common.models import NormalizedEvent


def _sanitize_for_json(value: Any) -> Any:
    """Recursively sanitize values for JSON serialization."""
    if isinstance(value, dict):
        return {k: _sanitize_for_json(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_sanitize_for_json(item) for item in value]
    elif isinstance(value, (int, float)):
        if math.isnan(value):
            return None
        try:
            if abs(value) > 1e308:
                return str(value)
        except (TypeError, ValueError):
            pass
        return value
    elif isinstance(value, str):
        return value
    elif value is None or value is ...:
        return None
    else:
        return str(value)


class JSONFormatter(BaseFormatter):
    """Formats normalized events as RFC 8259 compliant JSON.

    The JSON output includes:
    - All OCSF normalized fields
    - All original parsed fields preserved
    - Provenance metadata (event_id, raw_event_id, sha256)
    - Schema version
    """

    formatter_id = "json_formatter_v1"
    formatter_name = "JSON Formatter v1"
    formatter_version = "1.0.0"
    output_format = OutputFormat.JSON
    description = "Formats events as RFC 8259 compliant JSON"

    def format(self, event: NormalizedEvent) -> str:
        """Format a normalized event as JSON.

        Args:
            event: The normalized event to format.

        Returns:
            RFC 8259 compliant JSON string.
        """
        output: dict[str, Any] = {
            "event_id": event.event_id,
            "raw_event_id": event.raw_event_id,
            "source_id": event.source_id,
            "source_type": event.source_type,
            "format": event.format,
            "parser_id": event.parser_id,
            "parser_version": event.parser_version,
            "schema_version": event.schema_version,
            "event_timestamp": event.event_timestamp,
            "ingestion_timestamp": event.ingestion_timestamp,
            "sha256": event.sha256,
            "ocsf": _sanitize_for_json(event.ocsf or {}),
            "parsed_fields": _sanitize_for_json(event.parsed_fields or {}),
            "raw_payload": event.raw_payload,
        }

        return json.dumps(output, indent=2, ensure_ascii=False, sort_keys=False)
