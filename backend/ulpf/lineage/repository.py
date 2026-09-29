"""Lineage repository for ULPF Phase 6.

Manages event lineage relationships in PostgreSQL.

Extends the existing PostgreSQL metadata storage with lineage tables.

Schema:
    event_lineage:
        - id (UUID, primary key)
        - parent_event_id (VARCHAR, indexed)
        - child_event_id (VARCHAR, indexed)
        - relationship_type (VARCHAR)
        - raw_event_id (VARCHAR, indexed)
        - created_at (TIMESTAMPTZ)

Unique constraint: (parent_event_id, child_event_id, relationship_type)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from ulpf.common.models import EventEnvelope
from ulpf.lineage.models import LineageRecord, RelationshipType

logger = logging.getLogger("ulpf.lineage.repository")


LINEAGE_SCHEMA_SQL = """
-- Event lineage table for traceability
CREATE TABLE IF NOT EXISTS event_lineage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_event_id VARCHAR(64) NOT NULL,
    child_event_id VARCHAR(64) NOT NULL,
    relationship_type VARCHAR(32) NOT NULL,
    raw_event_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (parent_event_id, child_event_id, relationship_type)
);

CREATE INDEX IF NOT EXISTS idx_lineage_parent ON event_lineage(parent_event_id);
CREATE INDEX IF NOT EXISTS idx_lineage_child ON event_lineage(child_event_id);
CREATE INDEX IF NOT EXISTS idx_lineage_raw ON event_lineage(raw_event_id);
CREATE INDEX IF NOT EXISTS idx_lineage_type ON event_lineage(relationship_type);
"""


class LineageRepository:
    """Repository for event lineage relationships.

    Provides CRUD operations for lineage records and queries
    for ancestry/descendant lookups.
    """

    def __init__(
        self,
        connection_provider: Any = None,
    ) -> None:
        from ulpf.storage.postgres_adapter import PostgresAdapter

        self._postgres = connection_provider or PostgresAdapter()
        self._schema_extended = False

    def initialize_schema(self) -> None:
        """Initialize lineage tables if they don't exist."""
        if self._schema_extended:
            return

        try:
            with self._postgres.get_connection() as conn, conn.cursor() as cursor:
                cursor.execute(LINEAGE_SCHEMA_SQL)
            self._schema_extended = True
            logger.info("Lineage schema initialized")
        except Exception as exc:
            logger.error("Failed to initialize lineage schema: %s", exc)
            raise

    def record_lineage(
        self,
        parent_event_id: str,
        child_event_id: str,
        relationship_type: RelationshipType,
        raw_event_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Record a lineage relationship.

        Uses ON CONFLICT to handle idempotency.

        Args:
            parent_event_id: The parent event ID (e.g., raw_event_id for parsing).
            child_event_id: The child event ID (e.g., parsed event_id).
            relationship_type: Type of relationship (parsed_from, normalized_from).
            raw_event_id: The original raw event ID.
            metadata: Optional additional metadata.

        Returns:
            True if recorded successfully.
        """
        query = """
        INSERT INTO event_lineage (
            id, parent_event_id, child_event_id, relationship_type,
            raw_event_id, created_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (parent_event_id, child_event_id, relationship_type) DO NOTHING
        """

        now = datetime.now(timezone.utc)

        try:
            with self._postgres.get_connection() as conn, conn.cursor() as cursor:
                cursor.execute(
                    query,
                    (
                        str(uuid4()),
                        parent_event_id,
                        child_event_id,
                        relationship_type.value,
                        raw_event_id,
                        now,
                    ),
                )
            logger.debug(
                "Recorded lineage: parent=%s child=%s type=%s",
                parent_event_id,
                child_event_id,
                relationship_type.value,
            )
            return True

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Failed to record lineage: parent=%s child=%s error=%s",
                parent_event_id,
                child_event_id,
                exc,
            )
            return False

    def record_parsed_lineage(
        self,
        envelope: EventEnvelope,
    ) -> bool:
        """Record lineage for a parsed event.

        Creates relationship: raw_event_id -> parsed_event_id

        Args:
            envelope: The event envelope with parsed event.

        Returns:
            True if recorded successfully.
        """
        if envelope.parsed is None:
            logger.warning("Cannot record parsed lineage: no parsed event")
            return False

        return self.record_lineage(
            parent_event_id=envelope.raw.raw_event_id,
            child_event_id=envelope.parsed.event_id,
            relationship_type=RelationshipType.PARSED_FROM,
            raw_event_id=envelope.raw.raw_event_id,
            metadata={
                "parser_id": envelope.parser_id,
                "parser_version": envelope.parser_version,
            },
        )

    def record_normalized_lineage(
        self,
        envelope: EventEnvelope,
    ) -> bool:
        """Record lineage for a normalized event.

        Creates relationship: parsed_event_id -> normalized_event_id

        Args:
            envelope: The event envelope with normalized event.

        Returns:
            True if recorded successfully.
        """
        if envelope.parsed is None:
            logger.warning("Cannot record normalized lineage: no parsed event")
            return False
        if envelope.normalized is None:
            logger.warning("Cannot record normalized lineage: no normalized event")
            return False

        return self.record_lineage(
            parent_event_id=envelope.parsed.event_id,
            child_event_id=envelope.normalized.event_id,
            relationship_type=RelationshipType.NORMALIZED_FROM,
            raw_event_id=envelope.raw.raw_event_id,
            metadata={
                "parser_id": envelope.parser_id,
                "parser_version": envelope.parser_version,
                "schema_version": envelope.schema_version,
            },
        )

    def get_ancestors(
        self,
        event_id: str,
        relationship_type: RelationshipType | None = None,
    ) -> list[LineageRecord]:
        """Get all ancestors of an event.

        Args:
            event_id: The child event ID to find ancestors for.
            relationship_type: Optional filter by relationship type.

        Returns:
            List of lineage records representing ancestors.
        """
        if relationship_type:
            query = """
            SELECT * FROM event_lineage
            WHERE child_event_id = %s AND relationship_type = %s
            ORDER BY created_at DESC
            """
            params: tuple[str, ...] = (event_id, relationship_type.value)
        else:
            query = """
            SELECT * FROM event_lineage
            WHERE child_event_id = %s
            ORDER BY created_at DESC
            """
            params = (event_id,)

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [self._row_to_record(row) for row in rows]

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to get ancestors: event_id=%s error=%s", event_id, exc)
            return []

    def get_descendants(
        self,
        event_id: str,
        relationship_type: RelationshipType | None = None,
    ) -> list[LineageRecord]:
        """Get all descendants of an event.

        Args:
            event_id: The parent event ID to find descendants for.
            relationship_type: Optional filter by relationship type.

        Returns:
            List of lineage records representing descendants.
        """
        if relationship_type:
            query = """
            SELECT * FROM event_lineage
            WHERE parent_event_id = %s AND relationship_type = %s
            ORDER BY created_at DESC
            """
            params: tuple[str, ...] = (event_id, relationship_type.value)
        else:
            query = """
            SELECT * FROM event_lineage
            WHERE parent_event_id = %s
            ORDER BY created_at DESC
            """
            params = (event_id,)

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [self._row_to_record(row) for row in rows]

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Failed to get descendants: event_id=%s error=%s",
                event_id,
                exc,
            )
            return []

    def get_raw_ancestor(self, event_id: str) -> LineageRecord | None:
        """Get the raw event ancestor of an event.

        Follows the lineage chain to find the original raw event.

        Args:
            event_id: Any event ID in the chain.

        Returns:
            Lineage record for the raw event, or None if not found.
        """
        ancestors = self.get_ancestors(event_id, RelationshipType.PARSED_FROM)
        if ancestors:
            return ancestors[0]

        ancestors = self.get_ancestors(event_id)
        for ancestor in ancestors:
            if ancestor.relationship_type == RelationshipType.PARSED_FROM:
                return ancestor

        return None

    def get_lineage_by_raw_id(self, raw_event_id: str) -> list[LineageRecord]:
        """Get all lineage records related to a raw event.

        Args:
            raw_event_id: The raw event ID.

        Returns:
            All lineage records for this raw event.
        """
        query = """
        SELECT * FROM event_lineage
        WHERE raw_event_id = %s
        ORDER BY created_at ASC
        """

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(query, (raw_event_id,))
                rows = cursor.fetchall()
                return [self._row_to_record(row) for row in rows]

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Failed to get lineage by raw_id: raw_event_id=%s error=%s",
                raw_event_id,
                exc,
            )
            return []

    def lineage_exists(
        self,
        parent_event_id: str,
        child_event_id: str,
        relationship_type: RelationshipType,
    ) -> bool:
        """Check if a lineage relationship already exists.

        Args:
            parent_event_id: The parent event ID.
            child_event_id: The child event ID.
            relationship_type: Type of relationship.

        Returns:
            True if the relationship exists.
        """
        query = """
        SELECT 1 FROM event_lineage
        WHERE parent_event_id = %s
          AND child_event_id = %s
          AND relationship_type = %s
        """

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(
                    query,
                    (
                        parent_event_id,
                        child_event_id,
                        relationship_type.value,
                    ),
                )
                return cursor.fetchone() is not None

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Failed to check lineage existence: error=%s",
                exc,
            )
            return False

    def _row_to_record(self, row: Any) -> LineageRecord:
        """Convert a database row to a LineageRecord."""
        return LineageRecord(
            parent_event_id=row["parent_event_id"],
            child_event_id=row["child_event_id"],
            relationship_type=RelationshipType(row["relationship_type"]),
            raw_event_id=row["raw_event_id"],
            created_at=str(row["created_at"]),
        )
