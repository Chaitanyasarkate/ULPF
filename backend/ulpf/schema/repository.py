"""Schema repository for ULPF Phase 7.

PostgreSQL persistence for schema profiles and drift events.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ulpf.schema.models import DriftDetectionResult, DriftSeverity, SchemaProfile

logger = logging.getLogger("ulpf.schema.repository")

try:
    from psycopg2 import pool
    _PSYCOPG_AVAILABLE = True
except Exception:  # noqa: BLE001 pragma: no cover - optional dependency guard
    _PSYCOPG_AVAILABLE = False
    pool = None

SCHEMA_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_profiles (
    source_id VARCHAR(255) NOT NULL,
    schema_version VARCHAR(32) NOT NULL,
    required_fields JSONB DEFAULT '[]',
    optional_fields JSONB DEFAULT '[]',
    field_types JSONB DEFAULT '{}',
    active BOOLEAN DEFAULT TRUE,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (source_id, schema_version)
);

CREATE INDEX IF NOT EXISTS idx_schema_source ON schema_profiles(source_id);
CREATE INDEX IF NOT EXISTS idx_schema_active ON schema_profiles(active);

CREATE TABLE IF NOT EXISTS schema_drift_events (
    drift_id VARCHAR(64) PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL,
    raw_event_id VARCHAR(64) NOT NULL,
    source_id VARCHAR(255) NOT NULL,
    schema_version VARCHAR(32) NOT NULL,
    drift_types JSONB DEFAULT '[]',
    new_fields JSONB DEFAULT '[]',
    missing_required_fields JSONB DEFAULT '[]',
    missing_optional_fields JSONB DEFAULT '[]',
    type_changes JSONB DEFAULT '[]',
    severity VARCHAR(16) DEFAULT 'info',
    detected_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_drift_source ON schema_drift_events(source_id);
CREATE INDEX IF NOT EXISTS idx_drift_event ON schema_drift_events(event_id);
CREATE INDEX IF NOT EXISTS idx_drift_severity ON schema_drift_events(severity);
CREATE INDEX IF NOT EXISTS idx_drift_detected ON schema_drift_events(detected_at);
"""


class SchemaRepository:
    """Repository for schema profile and drift event persistence."""

    def __init__(
        self,
        postgres_adapter: Any = None,
    ) -> None:
        if not _PSYCOPG_AVAILABLE:
            raise RuntimeError("psycopg2 package not installed")

        from ulpf.storage.postgres_adapter import PostgresAdapter

        self._postgres = postgres_adapter or PostgresAdapter()
        self._schema_initialized = False

    def _ensure_schema(self) -> None:
        if self._schema_initialized:
            return
        try:
            with self._postgres.get_connection() as conn, conn.cursor() as cursor:
                cursor.execute(SCHEMA_SCHEMA_SQL)
            self._schema_initialized = True
            logger.info("Schema profiles and drift events schema initialized")
        except Exception as exc:
            logger.error("Failed to initialize schema schema: %s", exc)

    async def initialize_schema(self) -> None:
        self._ensure_schema()

    def upsert(self, schema: SchemaProfile) -> SchemaProfile:
        self._ensure_schema()
        query = """
        INSERT INTO schema_profiles (
            source_id, schema_version, required_fields, optional_fields,
            field_types, active, description, created_at, updated_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (source_id, schema_version) DO UPDATE SET
            required_fields = EXCLUDED.required_fields,
            optional_fields = EXCLUDED.optional_fields,
            field_types = EXCLUDED.field_types,
            active = EXCLUDED.active,
            description = EXCLUDED.description,
            updated_at = EXCLUDED.updated_at
        """

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(
                    query,
                    (
                        schema.source_id,
                        schema.schema_version,
                        json.dumps(schema.required_fields),
                        json.dumps(schema.optional_fields),
                        json.dumps(schema.field_types),
                        schema.active,
                        schema.description,
                        schema.created_at,
                        schema.updated_at,
                    ),
                )
            logger.debug(
                "Upserted schema: source=%s version=%s",
                schema.source_id,
                schema.schema_version,
            )
            return schema

        except Exception as exc:
            logger.error(
                "Failed to upsert schema: %s@%s error=%s",
                schema.source_id,
                schema.schema_version,
                exc,
            )
            raise

    def get_by_source_id(self, source_id: str) -> SchemaProfile | None:
        query = """
        SELECT * FROM schema_profiles
        WHERE source_id = %s AND active = TRUE
        ORDER BY schema_version DESC
        LIMIT 1
        """

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(query, (source_id,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_schema(row)
            return None

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to get schema: %s error=%s", source_id, exc)
            return None

    def get_all_versions(self, source_id: str) -> list[SchemaProfile]:
        query = """
        SELECT * FROM schema_profiles
        WHERE source_id = %s
        ORDER BY schema_version DESC
        """

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(query, (source_id,))
                rows = cursor.fetchall()
                return [self._row_to_schema(row) for row in rows]

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to get schema versions: %s error=%s", source_id, exc)
            return []

    def list_all(self) -> list[SchemaProfile]:
        query = """
        SELECT DISTINCT ON (source_id) *
        FROM schema_profiles
        WHERE active = TRUE
        ORDER BY source_id, schema_version DESC
        """

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(query)
                rows = cursor.fetchall()
                return [self._row_to_schema(row) for row in rows]

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to list schemas: %s", exc)
            return []

    def record_drift(self, result: DriftDetectionResult) -> bool:
        query = """
        INSERT INTO schema_drift_events (
            drift_id, event_id, raw_event_id, source_id, schema_version,
            drift_types, new_fields, missing_required_fields, missing_optional_fields,
            type_changes, severity, detected_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        """

        drift_id = f"drift-{result.event_id}"
        raw_event_id = result.raw_event_id or ""

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(
                    query,
                    (
                        drift_id,
                        result.event_id,
                        raw_event_id,
                        result.source_id,
                        result.schema_version,
                        json.dumps(result.drift_types),
                        json.dumps(result.new_fields),
                        json.dumps(result.missing_required_fields),
                        json.dumps(result.missing_optional_fields),
                        json.dumps(result.type_changes),
                        result.severity,
                        result.detected_at,
                    ),
                )
            logger.debug("Recorded drift event: %s", drift_id)
            return True

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to record drift: %s error=%s", drift_id, exc)
            return False

    def get_drift_history(
        self,
        source_id: str | None = None,
        limit: int = 100,
    ) -> tuple[list[DriftDetectionResult], int]:
        if source_id:
            count_query = "SELECT COUNT(*) FROM schema_drift_events WHERE source_id = %s"
            events_query = """
            SELECT * FROM schema_drift_events
            WHERE source_id = %s
            ORDER BY detected_at DESC
            LIMIT %s
            """
            params: tuple = (source_id, limit)
            count_params = (source_id,)
        else:
            count_query = "SELECT COUNT(*) FROM schema_drift_events"
            events_query = """
            SELECT * FROM schema_drift_events
            ORDER BY detected_at DESC
            LIMIT %s
            """
            params = (limit,)
            count_params = ()

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(count_query, count_params)
                row = cursor.fetchone()
                total = row["count"] if isinstance(row, dict) else row[0]

                cursor.execute(events_query, params)
                rows = cursor.fetchall()
                return [self._row_to_drift(row) for row in rows], total

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to get drift history: %s", exc)
            return [], 0

    def get_drift_by_event(self, event_id: str) -> DriftDetectionResult | None:
        query = "SELECT * FROM schema_drift_events WHERE event_id = %s LIMIT 1"

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(query, (event_id,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_drift(row)
            return None

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to get drift by event: %s error=%s", event_id, exc)
            return None

    def clear_drift_events(self) -> int:
        """Delete all schema drift events from the database.

        Used to reset the dashboard count when simulators are
        started, so each monitoring cycle begins with a clean count.

        Returns:
            Number of rows deleted.
        """
        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute("DELETE FROM schema_drift_events")
                return cursor.rowcount
        except Exception as exc:
            logger.error("Failed to clear drift events: %s", exc)
            return 0

    def _row_to_schema(self, row: Any) -> SchemaProfile:
        required = row.get("required_fields")
        if isinstance(required, str):
            required = json.loads(required)
        optional = row.get("optional_fields")
        if isinstance(optional, str):
            optional = json.loads(optional)
        field_types = row.get("field_types")
        if isinstance(field_types, str):
            field_types = json.loads(field_types)

        return SchemaProfile(
            source_id=row["source_id"],
            schema_version=row["schema_version"],
            required_fields=required or [],
            optional_fields=optional or [],
            field_types=field_types or {},
            active=row.get("active", True),
            description=row.get("description"),
            created_at=str(row.get("created_at", "")),
            updated_at=str(row.get("updated_at", "")),
        )

    def _row_to_drift(self, row: Any) -> DriftDetectionResult:
        drift_types = row.get("drift_types")
        if isinstance(drift_types, str):
            drift_types = json.loads(drift_types)
        new_fields = row.get("new_fields")
        if isinstance(new_fields, str):
            new_fields = json.loads(new_fields)
        missing_required = row.get("missing_required_fields")
        if isinstance(missing_required, str):
            missing_required = json.loads(missing_required)
        missing_optional = row.get("missing_optional_fields")
        if isinstance(missing_optional, str):
            missing_optional = json.loads(missing_optional)
        type_changes = row.get("type_changes")
        if isinstance(type_changes, str):
            type_changes = json.loads(type_changes)

        result = DriftDetectionResult(
            source_id=row["source_id"],
            schema_version=row["schema_version"],
            event_id=row["event_id"],
            drift_detected=True,
            drift_types=drift_types or [],
            new_fields=new_fields or [],
            missing_required_fields=missing_required or [],
            missing_optional_fields=missing_optional or [],
            type_changes=type_changes or [],
            severity=row.get("severity", DriftSeverity.INFO.value),
            detected_at=str(row.get("detected_at", "")),
        )
        return result
