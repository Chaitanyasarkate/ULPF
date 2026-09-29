"""Source repository for ULPF Phase 7.

PostgreSQL persistence for source profiles.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ulpf.onboarding.models import SourceProfile

logger = logging.getLogger("ulpf.onboarding.repository")

try:
    from psycopg2 import pool
    _PSYCOPG_AVAILABLE = True
except Exception:  # noqa: BLE001 pragma: no cover - optional dependency guard
    _PSYCOPG_AVAILABLE = False
    pool = None

SOURCE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS source_profiles (
    source_id VARCHAR(255) PRIMARY KEY,
    source_name VARCHAR(255) NOT NULL,
    source_type VARCHAR(64) NOT NULL,
    format VARCHAR(32) NOT NULL,
    parser_id VARCHAR(128) NOT NULL,
    parser_version VARCHAR(32) DEFAULT '1.0.0',
    normalizer_id VARCHAR(128),
    normalizer_version VARCHAR(32),
    schema_version VARCHAR(32) DEFAULT '1.0.0',
    enabled BOOLEAN DEFAULT TRUE,
    status VARCHAR(32) DEFAULT 'active',
    vendor VARCHAR(128),
    product VARCHAR(128),
    product_version VARCHAR(64),
    description TEXT,
    transport VARCHAR(64),
    configuration JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_source_type ON source_profiles(source_type);
CREATE INDEX IF NOT EXISTS idx_source_enabled ON source_profiles(enabled);
CREATE INDEX IF NOT EXISTS idx_source_parser ON source_profiles(parser_id);
"""


class SourceRepository:
    """Repository for source profile persistence."""

    def __init__(
        self,
        postgres_adapter: Any = None,
    ) -> None:
        if not _PSYCOPG_AVAILABLE:
            raise RuntimeError("psycopg2 package not installed")

        from ulpf.storage.postgres_adapter import PostgresAdapter

        self._postgres = postgres_adapter or PostgresAdapter()
        self._schema_initialized = False

    async def initialize_schema(self) -> None:
        if self._schema_initialized:
            return

        try:
            with self._postgres.get_connection() as conn, conn.cursor() as cursor:
                cursor.execute(SOURCE_SCHEMA_SQL)
            self._schema_initialized = True
            logger.info("Source profiles schema initialized")
        except Exception as exc:
            logger.error("Failed to initialize source schema: %s", exc)
            raise

    def insert(self, profile: SourceProfile) -> SourceProfile:
        query = """
        INSERT INTO source_profiles (
            source_id, source_name, source_type, format,
            parser_id, parser_version, normalizer_id, normalizer_version,
            schema_version, enabled, status, vendor, product,
            product_version, description, transport, configuration,
            created_at, updated_at
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (source_id) DO UPDATE SET
            source_name = EXCLUDED.source_name,
            source_type = EXCLUDED.source_type,
            format = EXCLUDED.format,
            parser_id = EXCLUDED.parser_id,
            parser_version = EXCLUDED.parser_version,
            normalizer_id = EXCLUDED.normalizer_id,
            normalizer_version = EXCLUDED.normalizer_version,
            schema_version = EXCLUDED.schema_version,
            enabled = EXCLUDED.enabled,
            status = EXCLUDED.status,
            vendor = EXCLUDED.vendor,
            product = EXCLUDED.product,
            product_version = EXCLUDED.product_version,
            description = EXCLUDED.description,
            transport = EXCLUDED.transport,
            configuration = EXCLUDED.configuration,
            updated_at = EXCLUDED.updated_at
        """

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(
                    query,
                    (
                        profile.source_id,
                        profile.source_name,
                        profile.source_type,
                        profile.format,
                        profile.parser_id,
                        profile.parser_version,
                        profile.normalizer_id,
                        profile.normalizer_version,
                        profile.schema_version,
                        profile.enabled,
                        profile.status,
                        profile.vendor,
                        profile.product,
                        profile.product_version,
                        profile.description,
                        profile.transport,
                        json.dumps(profile.configuration),
                        profile.created_at,
                        profile.updated_at,
                    ),
                )
            logger.debug("Inserted/updated source: %s", profile.source_id)
            return profile

        except Exception as exc:
            logger.error("Failed to insert source: %s error=%s", profile.source_id, exc)
            raise

    def update(self, profile: SourceProfile) -> SourceProfile:
        return self.insert(profile)

    def delete(self, source_id: str) -> bool:
        query = "DELETE FROM source_profiles WHERE source_id = %s"

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(query, (source_id,))
            logger.info("Deleted source: %s", source_id)
            return True

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to delete source: %s error=%s", source_id, exc)
            return False

    def get_by_source_id(self, source_id: str) -> SourceProfile | None:
        query = "SELECT * FROM source_profiles WHERE source_id = %s"

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(query, (source_id,))
                row = cursor.fetchone()
                if row:
                    return self._row_to_profile(row)
            return None

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to get source: %s error=%s", source_id, exc)
            return None

    def list_all(self) -> list[SourceProfile]:
        query = "SELECT * FROM source_profiles ORDER BY source_id"

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(query)
                rows = cursor.fetchall()
                return [self._row_to_profile(row) for row in rows]

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to list sources: %s", exc)
            return []

    def get_by_parser_id(self, parser_id: str) -> list[SourceProfile]:
        query = "SELECT * FROM source_profiles WHERE parser_id = %s ORDER BY source_id"

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(query, (parser_id,))
                rows = cursor.fetchall()
                return [self._row_to_profile(row) for row in rows]

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to get sources by parser: %s error=%s", parser_id, exc)
            return []

    def get_by_source_type(self, source_type: str) -> list[SourceProfile]:
        query = "SELECT * FROM source_profiles WHERE source_type = %s ORDER BY source_id"

        try:
            with self._postgres.get_cursor() as cursor:
                cursor.execute(query, (source_type,))
                rows = cursor.fetchall()
                return [self._row_to_profile(row) for row in rows]

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to get sources by type: %s error=%s", source_type, exc)
            return []

    def _row_to_profile(self, row: Any) -> SourceProfile:
        configuration = row.get("configuration")
        if isinstance(configuration, str):
            configuration = json.loads(configuration)

        return SourceProfile(
            source_id=row["source_id"],
            source_name=row["source_name"],
            source_type=row["source_type"],
            format=row["format"],
            parser_id=row["parser_id"],
            parser_version=row.get("parser_version", "1.0.0"),
            normalizer_id=row.get("normalizer_id"),
            normalizer_version=row.get("normalizer_version"),
            schema_version=row.get("schema_version", "1.0.0"),
            enabled=row.get("enabled", True),
            status=row.get("status", "active"),
            vendor=row.get("vendor"),
            product=row.get("product"),
            product_version=row.get("product_version"),
            description=row.get("description"),
            transport=row.get("transport"),
            configuration=configuration or {},
            created_at=str(row.get("created_at", "")),
            updated_at=str(row.get("updated_at", "")),
        )
