"""Unit tests for storage consumers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from ulpf.common.models import NormalizedEvent


class TestRawStorageConsumer:
    """Tests for RawStorageConsumer."""

    def test_metrics_initialization(self):
        """Test that metrics are initialized correctly."""
        from ulpf.storage.raw_storage_consumer import RawStorageConsumer

        with patch("ulpf.storage.raw_storage_consumer.MinIOAdapter") as mock_minio, \
             patch("ulpf.storage.raw_storage_consumer.PostgresAdapter") as mock_pg:
            mock_minio.return_value = MagicMock()
            mock_pg.return_value = MagicMock()

            consumer = RawStorageConsumer()

            assert consumer._stored_count == 0
            assert consumer._error_count == 0
            assert consumer._skipped_count == 0

    def test_metrics_return_dict(self):
        """Test that metrics returns a dictionary."""
        from ulpf.storage.raw_storage_consumer import RawStorageConsumer

        with patch("ulpf.storage.raw_storage_consumer.MinIOAdapter") as mock_minio, \
             patch("ulpf.storage.raw_storage_consumer.PostgresAdapter") as mock_pg:
            mock_minio.return_value = MagicMock()
            mock_pg.return_value = MagicMock()

            consumer = RawStorageConsumer()
            metrics = consumer.metrics()

            assert isinstance(metrics, dict)
            assert "stored_count" in metrics
            assert "error_count" in metrics
            assert "skipped_count" in metrics


class TestNormalizedStorageConsumer:
    """Tests for NormalizedStorageConsumer."""

    def test_metrics_initialization(self):
        """Test that metrics are initialized correctly."""
        from ulpf.storage.normalized_storage_consumer import NormalizedStorageConsumer

        with patch("ulpf.storage.normalized_storage_consumer.OpenSearchAdapter") as mock_os, \
             patch("ulpf.storage.normalized_storage_consumer.PostgresAdapter") as mock_pg:
            mock_os.return_value = MagicMock()
            mock_pg.return_value = MagicMock()

            consumer = NormalizedStorageConsumer()

            assert consumer._indexed_count == 0
            assert consumer._error_count == 0
            assert consumer._skipped_count == 0

    def test_metrics_return_dict(self):
        """Test that metrics returns a dictionary."""
        from ulpf.storage.normalized_storage_consumer import NormalizedStorageConsumer

        with patch("ulpf.storage.normalized_storage_consumer.OpenSearchAdapter") as mock_os, \
             patch("ulpf.storage.normalized_storage_consumer.PostgresAdapter") as mock_pg:
            mock_os.return_value = MagicMock()
            mock_pg.return_value = MagicMock()

            consumer = NormalizedStorageConsumer()
            metrics = consumer.metrics()

            assert isinstance(metrics, dict)
            assert "indexed_count" in metrics
            assert "error_count" in metrics


class TestStorageIntegration:
    """Integration-style tests for storage layer (mocked)."""

    def test_lossless_preservation_in_storage(self):
        """Test that all fields are preserved through storage pipeline."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = None

        original_event = NormalizedEvent(
            event_id="evt-123",
            raw_event_id="raw-456",
            source_id="fw-1",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
            parser_version="1.0.0",
            schema_version="1.0.0",
            event_timestamp="2026-09-07T08:01:17+00:00",
            ingestion_timestamp="2026-09-07T08:01:18+00:00",
            sha256="abc123",
            ocsf={
                "event": {"action": "allow", "severity": "high"},
                "source": {"ip": "10.0.0.1", "port": 12345},
                "destination": {"ip": "192.168.1.1", "port": 80},
                "network": {"protocol": "TCP"},
                "device": {"name": "fw-1"},
            },
            parsed_fields={
                "original_action": "ACCEPT",
                "custom_field": "preserve_me",
            },
            raw_payload="<58>Sep 07 08:01:17 original",
        )

        doc = adapter._build_document(original_event)

        assert doc["ocsf"]["event"]["action"] == "allow"
        assert doc["parsed_fields"]["original_action"] == "ACCEPT"
        assert doc["parsed_fields"]["custom_field"] == "preserve_me"
        assert doc["raw_payload"] == "<58>Sep 07 08:01:17 original"
        assert doc["parser_id"] == "firewall_syslog_v1"
        assert doc["parser_version"] == "1.0.0"
        assert doc["schema_version"] == "1.0.0"


class TestLineageResolution:
    """Tests for lineage resolution."""

    def test_event_has_raw_event_id(self):
        """Test that normalized events have raw_event_id for lineage."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "raw_event_id" in schema
        assert "event_id" in schema

    def test_raw_object_links_to_event(self):
        """Test that raw_object_metadata has foreign key to event_metadata."""
        from ulpf.storage.postgres_adapter import PostgresAdapter

        adapter = PostgresAdapter.__new__(PostgresAdapter)
        adapter._pool = MagicMock()

        schema = adapter.SCHEMA_SQL

        assert "REFERENCES event_metadata" in schema


class TestIdempotency:
    """Tests for idempotency guarantees."""

    def test_object_key_is_deterministic(self):
        """Test that object keys are deterministic for same input."""
        from ulpf.storage.minio_adapter import MinIOAdapter

        adapter = MinIOAdapter.__new__(MinIOAdapter)
        adapter._client = None

        key1 = adapter._generate_object_key("raw-123", "firewall", "2026-09-07T08:00:00+00:00")
        key2 = adapter._generate_object_key("raw-123", "firewall", "2026-09-07T08:00:00+00:00")

        assert key1 == key2

    def test_document_id_is_event_id(self):
        """Test that OpenSearch document ID is the event_id."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = None

        event = NormalizedEvent(
            event_id="evt-unique-123",
            raw_event_id="raw-456",
            ocsf={},
            parsed_fields={},
        )

        doc = adapter._build_document(event)

        assert doc["event_id"] == "evt-unique-123"
