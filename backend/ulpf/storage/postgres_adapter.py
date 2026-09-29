"""PostgreSQL adapter for ULPF Phase 5.

Provides metadata and lineage storage with schema management.

Architecture:
    - PostgreSQL stores event metadata and storage references
    - Enables raw -> normalized lineage resolution
    - NOT for storing complete raw payloads (use MinIO for that)

Tables:
    - event_metadata: Core event information
    - raw_object_metadata: MinIO storage references
    - normalized_object_metadata: OpenSearch storage references

Usage:
    adapter = PostgresAdapter()
    await adapter.initialize_schema()
    await adapter.insert_event_metadata(event)
    await adapter.get_raw_object_reference(raw_event_id)
"""

from __future__ import annotations

import logging
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("ulpf.storage.postgres")

try:
    from psycopg2 import pool

    try:
        from psycopg2.extras import RealDictCursor
    except ImportError:
        RealDictCursor = None

    _PSYCOPG_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency guard
    _PSYCOPG_AVAILABLE = False
    pool = None
    RealDictCursor = None

from ulpf.common.models import EventEnvelope, NormalizedEvent
from ulpf.config import get_settings


class PostgresError(Exception):
    """Base exception for PostgreSQL operations."""


class UniqueViolationError(PostgresError):
    """Raised when a unique constraint is violated."""


class ForeignKeyViolationError(PostgresError):
    """Raised when a foreign key constraint is violated."""


class PostgresAdapter:
    """PostgreSQL adapter for metadata and lineage storage.

    Manages event metadata, storage references, and lineage relationships.
    """

    SCHEMA_SQL = """
    -- Event metadata table
    CREATE TABLE IF NOT EXISTS event_metadata (
        event_id VARCHAR(64) PRIMARY KEY,
        raw_event_id VARCHAR(64) NOT NULL UNIQUE,
        source_id VARCHAR(255),
        source_type VARCHAR(64),
        format VARCHAR(64),
        ingestion_timestamp TIMESTAMPTZ NOT NULL,
        event_timestamp TIMESTAMPTZ,
        sha256 VARCHAR(64),
        parser_id VARCHAR(128),
        parser_version VARCHAR(32),
        schema_version VARCHAR(32) DEFAULT '1.0.0',
        processing_status VARCHAR(32) DEFAULT 'received',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_event_metadata_raw_event_id ON event_metadata(raw_event_id);
    CREATE INDEX IF NOT EXISTS idx_event_metadata_source_id ON event_metadata(source_id);
    CREATE INDEX IF NOT EXISTS idx_event_metadata_source_type ON event_metadata(source_type);
    CREATE INDEX IF NOT EXISTS idx_event_metadata_timestamp ON event_metadata(ingestion_timestamp);

    -- Raw object metadata (MinIO references)
    CREATE TABLE IF NOT EXISTS raw_object_metadata (
        raw_event_id VARCHAR(64) PRIMARY KEY REFERENCES event_metadata(raw_event_id) ON DELETE CASCADE,
        object_key VARCHAR(512) NOT NULL,
        bucket VARCHAR(128) NOT NULL,
        sha256 VARCHAR(64) NOT NULL,
        size_bytes BIGINT,
        storage_status VARCHAR(32) DEFAULT 'stored',
        created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_raw_object_bucket ON raw_object_metadata(bucket);
    CREATE INDEX IF NOT EXISTS idx_raw_object_sha256 ON raw_object_metadata(sha256);

    -- Normalized object metadata (OpenSearch references)
    CREATE TABLE IF NOT EXISTS normalized_object_metadata (
        event_id VARCHAR(64) PRIMARY KEY REFERENCES event_metadata(event_id) ON DELETE CASCADE,
        index_name VARCHAR(128) NOT NULL,
        document_id VARCHAR(64) NOT NULL,
        schema_version VARCHAR(32),
        created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_normalized_index ON normalized_object_metadata(index_name);
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        db: str | None = None,
        user: str | None = None,
        password: str | None = None,
        min_pool: int | None = None,
        max_pool: int | None = None,
    ) -> None:
        if not _PSYCOPG_AVAILABLE:
            raise RuntimeError("psycopg2 package not installed")

        settings = get_settings()
        self.host = host or settings.postgres.host
        self.port = port or settings.postgres.port
        self.db = db or settings.postgres.db
        self.user = user or settings.postgres.user
        self.password = password or settings.postgres.password
        self.min_pool = min_pool or settings.postgres.min_pool
        self.max_pool = max_pool or settings.postgres.max_pool

        self._pool: pool.ThreadedConnectionPool | None = None

    def _get_dsn(self) -> str:
        """Build the connection string."""
        return f"host={self.host} port={self.port} dbname={self.db} user={self.user} password={self.password} connect_timeout=2"

    @property
    def pool(self) -> pool.ThreadedConnectionPool:
        if self._pool is None:
            self._pool = pool.ThreadedConnectionPool(
                self.min_pool,
                self.max_pool,
                self._get_dsn(),
            )
        return self._pool

    @contextmanager
    def get_connection(self) -> Generator[Any, None, None]:
        """Get a connection from the pool."""
        conn = self.pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.pool.putconn(conn)

    @contextmanager
    def get_cursor(self) -> Generator[Any, None, None]:
        """Get a cursor with automatic commit/rollback."""
        with self.get_connection() as conn:
            cursor_factory = RealDictCursor if RealDictCursor else None
            cursor = conn.cursor(cursor_factory=cursor_factory)
            try:
                yield cursor
            finally:
                cursor.close()

    async def initialize_schema(self) -> None:
        """Initialize the database schema.

        Creates all required tables and indexes if they don't exist.
        """
        try:
            with self.get_connection() as conn, conn.cursor() as cursor:
                cursor.execute(self.SCHEMA_SQL)
            logger.info("PostgreSQL schema initialized")
        except Exception as exc:
            logger.error("Failed to initialize schema: %s", exc)
            raise PostgresError(f"Failed to initialize schema: {exc}") from exc

    async def insert_event_metadata(
        self,
        envelope: EventEnvelope,
        processing_status: str = "received",
    ) -> bool:
        """Insert or update event metadata.

        Uses ON CONFLICT to handle idempotency.

        Args:
            envelope: The event envelope to store metadata for.
            processing_status: Current processing status.

        Returns:
            True if successful.
        """
        now = datetime.now(timezone.utc)

        query = """
        INSERT INTO event_metadata (
            event_id, raw_event_id, source_id, source_type, format,
            ingestion_timestamp, event_timestamp, sha256, parser_id,
            parser_version, schema_version, processing_status, updated_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (event_id) DO UPDATE SET
            processing_status = EXCLUDED.processing_status,
            updated_at = EXCLUDED.updated_at
        """

        event_id = envelope.event_id or envelope.raw.raw_event_id

        try:
            with self.get_connection() as conn, conn.cursor() as cursor:
                cursor.execute(
                    query,
                    (
                        event_id,
                        envelope.raw.raw_event_id,
                        envelope.raw.source_id,
                        envelope.raw.source_type,
                        envelope.raw.format,
                        envelope.raw.received_at,
                        envelope.parsed.event_timestamp if envelope.parsed else None,
                        envelope.sha256,
                        envelope.parser_id,
                        envelope.parser_version,
                        envelope.schema_version,
                        processing_status,
                        now,
                    ),
                )
            logger.debug(
                "Inserted event metadata: event_id=%s raw_event_id=%s",
                event_id,
                envelope.raw.raw_event_id,
            )
            return True

        except Exception as exc:
            logger.error(
                "Failed to insert event metadata: event_id=%s error=%s",
                event_id,
                exc,
            )
            raise PostgresError(f"Failed to insert event metadata: {exc}") from exc

    async def insert_normalized_event_metadata(
        self,
        event: NormalizedEvent,
        index_name: str,
    ) -> bool:
        """Insert or update normalized event metadata.

        Args:
            event: The normalized event.
            index_name: The OpenSearch index containing the event.

        Returns:
            True if successful.
        """
        query = """
        INSERT INTO normalized_object_metadata (
            event_id, index_name, document_id, schema_version
        ) VALUES (
            %s, %s, %s, %s
        )
        ON CONFLICT (event_id) DO UPDATE SET
            index_name = EXCLUDED.index_name,
            document_id = EXCLUDED.document_id
        """

        try:
            with self.get_connection() as conn, conn.cursor() as cursor:
                cursor.execute(
                    query,
                    (
                        event.event_id,
                        index_name,
                        event.event_id,
                        event.schema_version,
                    ),
                )
            return True

        except Exception as exc:
            logger.error(
                "Failed to insert normalized metadata: event_id=%s error=%s",
                event.event_id,
                exc,
            )
            raise PostgresError(f"Failed to insert normalized metadata: {exc}") from exc

    async def insert_raw_object_metadata(
        self,
        raw_event_id: str,
        object_key: str,
        bucket: str,
        sha256: str,
        size_bytes: int = 0,
    ) -> bool:
        """Insert or update raw object metadata.

        Args:
            raw_event_id: The raw event identifier.
            object_key: MinIO object key.
            bucket: MinIO bucket name.
            sha256: SHA-256 hash of the raw payload.
            size_bytes: Size of the stored object.

        Returns:
            True if successful.
        """
        query = """
        INSERT INTO raw_object_metadata (
            raw_event_id, object_key, bucket, sha256, size_bytes, storage_status
        ) VALUES (
            %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (raw_event_id) DO UPDATE SET
            object_key = EXCLUDED.object_key,
            bucket = EXCLUDED.bucket,
            sha256 = EXCLUDED.sha256,
            size_bytes = EXCLUDED.size_bytes,
            storage_status = EXCLUDED.storage_status
        """

        try:
            with self.get_connection() as conn, conn.cursor() as cursor:
                cursor.execute(
                    query,
                    (
                        raw_event_id,
                        object_key,
                        bucket,
                        sha256,
                        size_bytes,
                        "stored",
                    ),
                )
            return True

        except Exception as exc:
            logger.error(
                "Failed to insert raw object metadata: raw_event_id=%s error=%s",
                raw_event_id,
                exc,
            )
            raise PostgresError(f"Failed to insert raw object metadata: {exc}") from exc

    async def get_event_metadata(self, event_id: str) -> dict[str, Any] | None:
        """Get event metadata by event_id.

        Args:
            event_id: The event identifier.

        Returns:
            Event metadata dict or None.
        """
        query = "SELECT * FROM event_metadata WHERE event_id = %s"

        try:
            with self.get_cursor() as cursor:
                cursor.execute(query, (event_id,))
                result = cursor.fetchone()
                return dict(result) if result else None

        except Exception as exc:
            logger.error("Failed to get event metadata: event_id=%s error=%s", event_id, exc)
            return None

    async def get_event_by_raw_id(self, raw_event_id: str) -> dict[str, Any] | None:
        """Get event metadata by raw_event_id.

        Args:
            raw_event_id: The raw event identifier.

        Returns:
            Event metadata dict or None.
        """
        query = "SELECT * FROM event_metadata WHERE raw_event_id = %s"

        try:
            with self.get_cursor() as cursor:
                cursor.execute(query, (raw_event_id,))
                result = cursor.fetchone()
                return dict(result) if result else None

        except Exception as exc:
            logger.error(
                "Failed to get event by raw_id: raw_event_id=%s error=%s",
                raw_event_id,
                exc,
            )
            return None

    async def get_raw_object_reference(self, raw_event_id: str) -> dict[str, Any] | None:
        """Get MinIO storage reference for a raw event.

        Enables: normalized event -> raw_event_id -> MinIO object

        Args:
            raw_event_id: The raw event identifier.

        Returns:
            Raw object metadata or None.
        """
        query = "SELECT * FROM raw_object_metadata WHERE raw_event_id = %s"

        try:
            with self.get_cursor() as cursor:
                cursor.execute(query, (raw_event_id,))
                result = cursor.fetchone()
                return dict(result) if result else None

        except Exception as exc:
            logger.error(
                "Failed to get raw object reference: raw_event_id=%s error=%s",
                raw_event_id,
                exc,
            )
            return None

    async def get_normalized_object_reference(self, event_id: str) -> dict[str, Any] | None:
        """Get OpenSearch storage reference for a normalized event.

        Args:
            event_id: The event identifier.

        Returns:
            Normalized object metadata or None.
        """
        query = "SELECT * FROM normalized_object_metadata WHERE event_id = %s"

        try:
            with self.get_cursor() as cursor:
                cursor.execute(query, (event_id,))
                result = cursor.fetchone()
                return dict(result) if result else None

        except Exception as exc:
            logger.error(
                "Failed to get normalized reference: event_id=%s error=%s",
                event_id,
                exc,
            )
            return None

    async def update_processing_status(
        self,
        raw_event_id: str,
        status: str,
    ) -> bool:
        """Update the processing status of an event.

        Args:
            raw_event_id: The raw event identifier.
            status: New processing status.

        Returns:
            True if updated.
        """
        query = """
        UPDATE event_metadata
        SET processing_status = %s, updated_at = %s
        WHERE raw_event_id = %s
        """

        try:
            with self.get_connection() as conn, conn.cursor() as cursor:
                cursor.execute(query, (status, datetime.now(timezone.utc), raw_event_id))
            return True

        except Exception as exc:
            logger.error(
                "Failed to update status: raw_event_id=%s status=%s error=%s",
                raw_event_id,
                status,
                exc,
            )
            return False

    async def health_check(self) -> bool:
        """Check if PostgreSQL is reachable.

        Returns:
            True if PostgreSQL is healthy, False otherwise.
        """
        try:
            with self.get_cursor() as cursor:
                cursor.execute("SELECT 1")
            return True
        except Exception:
            return False

    def close(self) -> None:
        """Close all connections in the pool."""
        if self._pool:
            self._pool.closeall()
            self._pool = None
            logger.info("PostgreSQL connection pool closed")
