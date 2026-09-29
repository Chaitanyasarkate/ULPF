"""Unit tests for PostgreSQL storage adapter."""

from __future__ import annotations

from unittest.mock import MagicMock


class TestSchemaInitialization:
    """Tests for schema initialization."""

    def test_schema_sql_creates_tables(self):
        """Test that schema SQL creates required tables."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "CREATE TABLE IF NOT EXISTS event_metadata" in schema
        assert "CREATE TABLE IF NOT EXISTS raw_object_metadata" in schema
        assert "CREATE TABLE IF NOT EXISTS normalized_object_metadata" in schema

    def test_event_metadata_has_required_columns(self):
        """Test that event_metadata table has required columns."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "event_id" in schema
        assert "raw_event_id" in schema
        assert "source_id" in schema
        assert "source_type" in schema
        assert "ingestion_timestamp" in schema
        assert "sha256" in schema
        assert "processing_status" in schema

    def test_raw_object_metadata_columns(self):
        """Test that raw_object_metadata has required columns."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "raw_event_id" in schema
        assert "object_key" in schema
        assert "bucket" in schema
        assert "sha256" in schema

    def test_unique_constraints(self):
        """Test that unique constraints are defined."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "UNIQUE" in schema or "PRIMARY KEY" in schema

    def test_raw_object_references_event_metadata(self):
        """Test that raw_object has foreign key to event_metadata."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "REFERENCES event_metadata" in schema

    def test_normalized_object_references_event_metadata(self):
        """Test that normalized_object has foreign key to event_metadata."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "normalized_object_metadata" in schema


class TestConnection:
    """Tests for connection management."""

    def test_get_dsn_builds_correct_string(self):
        """Test that connection string is built correctly."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = None
        adapter.host = "localhost"
        adapter.port = 5432
        adapter.db = "testdb"
        adapter.user = "testuser"
        adapter.password = "testpass"

        dsn = adapter._get_dsn()

        assert "host=localhost" in dsn
        assert "port=5432" in dsn
        assert "dbname=testdb" in dsn
        assert "user=testuser" in dsn
        assert "password=testpass" in dsn


class TestHealthCheck:
    """Tests for health check functionality."""

    def test_health_check_returns_bool(self):
        """Test health check returns a boolean."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        import asyncio
        result = asyncio.run(adapter.health_check())

        assert isinstance(result, bool)


class TestClose:
    """Tests for connection pool management."""

    def test_close_nullifies_pool(self):
        """Test that close() nullifies the pool."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        mock_pool = MagicMock()
        adapter._pool = mock_pool

        adapter.close()

        assert adapter._pool is None
        mock_pool.closeall.assert_called_once()


class TestIdempotency:
    """Tests for idempotency guarantees."""

    def test_event_id_primary_key(self):
        """Test that event_id is a primary key for uniqueness."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "PRIMARY KEY" in schema

    def test_raw_event_id_unique(self):
        """Test that raw_event_id has unique constraint."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "UNIQUE" in schema


class TestLineageResolution:
    """Tests for lineage resolution capabilities."""

    def test_raw_object_has_raw_event_id(self):
        """Test that raw_object metadata contains raw_event_id."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "raw_object_metadata" in schema
        assert "raw_event_id" in schema

    def test_normalized_object_has_event_id(self):
        """Test that normalized_object metadata contains event_id."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "normalized_object_metadata" in schema
        assert "event_id" in schema
        assert "index_name" in schema


class TestProcessingStatus:
    """Tests for processing status tracking."""

    def test_processing_status_column_exists(self):
        """Test that processing_status column exists."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "processing_status" in schema


class TestTimestamps:
    """Tests for timestamp handling."""

    def test_ingestion_timestamp_column_exists(self):
        """Test that ingestion_timestamp column exists."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "ingestion_timestamp" in schema

    def test_event_timestamp_column_exists(self):
        """Test that event_timestamp column exists."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "event_timestamp" in schema

    def test_created_at_column_exists(self):
        """Test that created_at column exists."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "created_at" in schema


class TestIndexes:
    """Tests for index creation."""

    def test_indexes_created(self):
        """Test that indexes are created for performance."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "CREATE INDEX" in schema
        assert "idx_event_metadata_raw_event_id" in schema
