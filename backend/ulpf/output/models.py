"""Data models for ULPF Phase 9A output conversion."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ConversionMetadata:
    """Metadata about a conversion operation."""

    event_id: str
    raw_event_id: str
    input_format: str
    output_format: str
    formatter_id: str
    formatter_version: str
    schema_version: str
    conversion_timestamp: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "raw_event_id": self.raw_event_id,
            "input_format": self.input_format,
            "output_format": self.output_format,
            "formatter_id": self.formatter_id,
            "formatter_version": self.formatter_version,
            "schema_version": self.schema_version,
            "conversion_timestamp": self.conversion_timestamp,
        }


@dataclass
class ConversionResult:
    """Result of an event conversion operation."""

    metadata: ConversionMetadata
    payload: str
    original_event_preserved: bool = True
    custom_fields_preserved: bool = True
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "payload": self.payload,
            "original_event_preserved": self.original_event_preserved,
            "custom_fields_preserved": self.custom_fields_preserved,
            "warnings": self.warnings,
        }

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> ConversionResult:
        """Create from API response dict."""
        metadata = ConversionMetadata(
            event_id=data["event_id"],
            raw_event_id=data["raw_event_id"],
            input_format=data.get("input_format", ""),
            output_format=data["output_format"],
            formatter_id=data["formatter_id"],
            formatter_version=data["formatter_version"],
            schema_version=data.get("schema_version", "1.0.0"),
            conversion_timestamp=data.get("conversion_timestamp", _utcnow_iso()),
        )
        return cls(
            metadata=metadata,
            payload=data["payload"],
            original_event_preserved=data.get("original_event_preserved", True),
            custom_fields_preserved=data.get("custom_fields_preserved", True),
            warnings=data.get("warnings", []),
        )
