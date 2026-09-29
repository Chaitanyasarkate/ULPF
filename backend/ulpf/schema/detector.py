"""Schema drift detector for ULPF Phase 7.

Detects changes in event structure compared to expected schemas.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ulpf.schema.models import (
    DriftDetectionResult,
    DriftEvent,
    SchemaProfile,
)

if TYPE_CHECKING:
    from ulpf.common.models import EventEnvelope

logger = logging.getLogger("ulpf.schema.detector")


class SchemaDriftDetector:
    """Detects schema drift in parsed events.

    Compares incoming event fields against registered schema profiles
    and reports any discrepancies while preserving the original event.
    """

    def __init__(
        self,
        schema_repository: Any = None,
        drift_publisher: Any = None,
    ) -> None:
        from ulpf.schema.repository import SchemaRepository

        self._schema_repo = schema_repository or SchemaRepository()
        self._drift_publisher = drift_publisher
        self._detection_cache: dict[str, SchemaProfile] = {}

    def register_schema(self, schema: SchemaProfile) -> SchemaProfile:
        result = self._schema_repo.upsert(schema)
        self._detection_cache[schema.source_id] = schema
        logger.info(
            "Registered schema for source=%s version=%s fields=%d",
            schema.source_id,
            schema.schema_version,
            len(schema.required_fields) + len(schema.optional_fields),
        )
        return result

    def get_schema(self, source_id: str) -> SchemaProfile | None:
        if source_id in self._detection_cache:
            return self._detection_cache[source_id]

        schema = self._schema_repo.get_by_source_id(source_id)
        if schema:
            self._detection_cache[source_id] = schema
        return schema

    def detect_drift(
        self,
        envelope: EventEnvelope,
    ) -> DriftDetectionResult | None:
        if not envelope.parsed:
            return None

        source_id = envelope.parsed.source_id
        schema = self.get_schema(source_id)

        if not schema:
            logger.debug("No schema registered for source: %s", source_id)
            return None

        result = DriftDetectionResult(
            source_id=source_id,
            schema_version=schema.schema_version,
            event_id=envelope.parsed.event_id,
        )

        incoming_fields = set(envelope.parsed.extracted.keys())
        expected_required = set(schema.required_fields)
        expected_optional = set(schema.optional_fields)
        expected_all = expected_required | expected_optional

        for field_name in incoming_fields:
            if field_name not in expected_all:
                result.add_new_field(field_name)

        missing_required = expected_required - incoming_fields
        for field_name in missing_required:
            result.add_missing_required_field(field_name)

        missing_optional = expected_optional - incoming_fields
        for field_name in missing_optional:
            result.add_missing_optional_field(field_name)

        for field_name in incoming_fields & expected_all:
            expected_type = schema.get_expected_type(field_name)
            if expected_type:
                actual_type = self._infer_type(envelope.parsed.extracted[field_name])
                if actual_type != expected_type:
                    result.add_type_change(field_name, expected_type, actual_type)

        if result.drift_detected:
            logger.info(
                "Schema drift detected: source=%s event=%s drift=%s severity=%s",
                source_id,
                envelope.parsed.event_id,
                result.drift_types,
                result.severity,
            )

        return result

    def detect_and_publish(
        self,
        envelope: EventEnvelope,
    ) -> DriftDetectionResult | None:
        """Synchronous version: detect drift, persist to PostgreSQL, and publish to Kafka."""
        result = self.detect_drift(envelope)

        if result and result.drift_detected:
            # Persist to PostgreSQL (sync psycopg2)
            try:
                self._schema_repo.record_drift(result)
            except Exception as exc:
                logger.warning("Failed to record drift in PostgreSQL: %s", exc)

            # Publish to Kafka if a publisher is configured
            if self._drift_publisher:
                drift_event = DriftEvent(
                    drift_id=f"drift-{envelope.parsed.event_id if envelope.parsed else 'unknown'}",
                    event_id=result.event_id,
                    raw_event_id=envelope.raw.raw_event_id,
                    source_id=result.source_id,
                    schema_version=result.schema_version,
                    drift_types=result.drift_types,
                    new_fields=result.new_fields,
                    missing_fields=result.missing_required_fields,
                    type_changes=result.type_changes,
                    severity=result.severity,
                )
                try:
                    self._drift_publisher.publish_drift(drift_event)
                except Exception as exc:
                    logger.warning("Failed to publish drift event: %s", exc)
                logger.debug("Published drift event: %s", drift_event.drift_id)

        return result

    async def detect_and_publish_async(
        self,
        envelope: EventEnvelope,
    ) -> DriftDetectionResult | None:
        """Async version for callers that are already in an async context."""
        return self.detect_and_publish(envelope)

    def list_schemas(self, source_type: str | None = None) -> list[SchemaProfile]:
        schemas = self._schema_repo.list_all()
        if source_type:
            schemas = [s for s in schemas if s.source_id.startswith(source_type)]
        return schemas

    def get_drift_history(
        self,
        source_id: str | None = None,
        limit: int = 100,
    ) -> tuple[list[DriftDetectionResult], int]:
        return self._schema_repo.get_drift_history(source_id, limit)

    @staticmethod
    def _infer_type(value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, float):
            return "float"
        if isinstance(value, str):
            return "string"
        if isinstance(value, dict):
            return "object"
        if isinstance(value, list):
            return "array"
        return "unknown"
