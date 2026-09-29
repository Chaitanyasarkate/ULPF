"""Schema profile models for ULPF Phase 7."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DriftType(str, Enum):
    NEW_FIELD = "new_field"
    MISSING_REQUIRED_FIELD = "missing_required_field"
    MISSING_OPTIONAL_FIELD = "missing_optional_field"
    TYPE_CHANGE = "type_change"
    VALUE_CHANGE = "value_change"

    @classmethod
    def values(cls) -> list[str]:
        return [e.value for e in cls]


class DriftSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"

    @classmethod
    def values(cls) -> list[str]:
        return [e.value for e in cls]


@dataclass
class SchemaProfile:
    """Expected schema definition for a source.

    Defines required and optional fields, along with expected types
    for schema drift detection.
    """

    source_id: str
    schema_version: str
    required_fields: list[str] = field(default_factory=list)
    optional_fields: list[str] = field(default_factory=list)
    field_types: dict[str, str] = field(default_factory=dict)
    active: bool = True
    description: str | None = None
    created_at: str = field(default_factory=_utcnow_iso)
    updated_at: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "schema_version": self.schema_version,
            "required_fields": list(self.required_fields),
            "optional_fields": list(self.optional_fields),
            "field_types": dict(self.field_types),
            "active": self.active,
            "description": self.description,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SchemaProfile:
        return cls(
            source_id=data["source_id"],
            schema_version=data["schema_version"],
            required_fields=data.get("required_fields", []),
            optional_fields=data.get("optional_fields", []),
            field_types=data.get("field_types", {}),
            active=data.get("active", True),
            description=data.get("description"),
            created_at=data.get("created_at", _utcnow_iso()),
            updated_at=data.get("updated_at", _utcnow_iso()),
        )

    def get_all_fields(self) -> set[str]:
        return set(self.required_fields) | set(self.optional_fields)

    def is_required(self, field_name: str) -> bool:
        return field_name in self.required_fields

    def is_optional(self, field_name: str) -> bool:
        return field_name in self.optional_fields

    def get_expected_type(self, field_name: str) -> str | None:
        return self.field_types.get(field_name)


@dataclass
class DriftDetectionResult:
    """Result of a schema drift detection operation."""

    source_id: str
    schema_version: str
    event_id: str
    raw_event_id: str = ""
    drift_detected: bool = False
    drift_types: list[str] = field(default_factory=list)
    new_fields: list[str] = field(default_factory=list)
    missing_required_fields: list[str] = field(default_factory=list)
    missing_optional_fields: list[str] = field(default_factory=list)
    type_changes: list[dict[str, str]] = field(default_factory=list)
    severity: str = DriftSeverity.INFO.value
    detected_at: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "raw_event_id": self.raw_event_id,
            "drift_detected": self.drift_detected,
            "drift_types": list(self.drift_types),
            "new_fields": list(self.new_fields),
            "missing_required_fields": list(self.missing_required_fields),
            "missing_optional_fields": list(self.missing_optional_fields),
            "type_changes": list(self.type_changes),
            "severity": self.severity,
            "detected_at": self.detected_at,
        }

    def add_new_field(self, field_name: str) -> None:
        if field_name not in self.new_fields:
            self.new_fields.append(field_name)
            self.drift_types.append(DriftType.NEW_FIELD.value)
            self.drift_detected = True
            self._update_severity()

    def add_missing_required_field(self, field_name: str) -> None:
        if field_name not in self.missing_required_fields:
            self.missing_required_fields.append(field_name)
            self.drift_types.append(DriftType.MISSING_REQUIRED_FIELD.value)
            self.drift_detected = True
            self._update_severity(DriftSeverity.ERROR)

    def add_missing_optional_field(self, field_name: str) -> None:
        if field_name not in self.missing_optional_fields:
            self.missing_optional_fields.append(field_name)
            self.drift_types.append(DriftType.MISSING_OPTIONAL_FIELD.value)
            self.drift_detected = True

    def add_type_change(self, field_name: str, expected: str, actual: str) -> None:
        self.type_changes.append({
            "field": field_name,
            "expected_type": expected,
            "actual_type": actual,
        })
        if DriftType.TYPE_CHANGE.value not in self.drift_types:
            self.drift_types.append(DriftType.TYPE_CHANGE.value)
        self.drift_detected = True
        self._update_severity(DriftSeverity.WARNING)

    def _update_severity(self, min_severity: DriftSeverity | None = None) -> None:
        severity_order = [DriftSeverity.INFO, DriftSeverity.WARNING, DriftSeverity.ERROR]
        current_idx = severity_order.index(DriftSeverity(self.severity))
        target_idx = current_idx

        if min_severity:
            target_idx = max(target_idx, severity_order.index(min_severity))

        if DriftType.MISSING_REQUIRED_FIELD.value in self.drift_types:
            target_idx = max(target_idx, severity_order.index(DriftSeverity.ERROR))
        elif DriftType.TYPE_CHANGE.value in self.drift_types:
            target_idx = max(target_idx, severity_order.index(DriftSeverity.WARNING))

        self.severity = severity_order[target_idx].value


@dataclass
class DriftEvent:
    """Kafka event published when schema drift is detected."""

    drift_id: str
    event_id: str
    raw_event_id: str
    source_id: str
    schema_version: str
    drift_types: list[str]
    new_fields: list[str]
    missing_fields: list[str]
    type_changes: list[dict[str, str]]
    severity: str
    detected_at: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "drift_id": self.drift_id,
            "event_id": self.event_id,
            "raw_event_id": self.raw_event_id,
            "source_id": self.source_id,
            "schema_version": self.schema_version,
            "drift_types": list(self.drift_types),
            "new_fields": list(self.new_fields),
            "missing_fields": list(self.missing_fields),
            "type_changes": list(self.type_changes),
            "severity": self.severity,
            "detected_at": self.detected_at,
        }
