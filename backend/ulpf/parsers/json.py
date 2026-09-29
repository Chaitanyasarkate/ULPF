"""JSON parser for ULPF Phase 3."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from ulpf.common.models import EventEnvelope, ParsedEvent, SourceType
from ulpf.parsers.base import BaseParser

logger = logging.getLogger("ulpf.parsers.json")


class RouterJsonParser(BaseParser):
    """Parser for Router JSON events."""

    parser_id = "router_json_v1"
    parser_name = "Router JSON Parser v1"
    source_type = SourceType.ROUTER.value
    format = "json"
    parser_version = "1.0.0"
    description = "Parses router JSON log events"

    def parse(self, envelope: EventEnvelope) -> ParsedEvent:
        try:
            data = json.loads(envelope.raw.payload)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON payload: {exc}") from exc

        if not isinstance(data, dict):
            raise TypeError(f"Expected JSON object, got {type(data).__name__}")

        extracted: dict[str, Any] = {}
        for key, value in data.items():
            if value is not None:
                extracted[key] = value

        event_timestamp = data.get("timestamp")
        if isinstance(event_timestamp, str) and event_timestamp:
            event_timestamp = str(event_timestamp)
        else:
            event_timestamp = None

        return ParsedEvent(
            event_id=envelope.parsed.event_id if envelope.parsed else str(uuid.uuid4()),
            raw_event_id=envelope.raw_event_id,
            source_id=envelope.raw.source_id,
            source_type=envelope.raw.source_type,
            format=envelope.raw.format,
            parser_id=self.parser_id,
            parser_version=self.parser_version,
            extracted=extracted,
            event_timestamp=event_timestamp,
        )
