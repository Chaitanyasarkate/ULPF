"""Unit tests for OpenSearch storage adapter."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

from ulpf.common.models import NormalizedEvent


class TestIndexNaming:
    """Tests for date-based index naming."""

    def test_index_name_with_timestamp(self):
        """Test index name generation with timestamp."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = None
        adapter.host = "localhost"
        adapter.port = 9200
        adapter.use_ssl = False
        adapter.verify_certs = False
        adapter.index_prefix = "ulpf"

        name = adapter._get_index_name("2026-09-07T08:01:17+00:00")

        assert name == "ulpf-events-2026.09.07"

    def test_index_name_without_timestamp(self):
        """Test index name generation without timestamp uses current date."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = None
        adapter.host = "localhost"
        adapter.port = 9200
        adapter.use_ssl = False
        adapter.verify_certs = False
        adapter.index_prefix = "ulpf"

        name = adapter._get_index_name()

        now = datetime.now(timezone.utc)
        expected = f"ulpf-events-{now.strftime('%Y.%m.%d')}"
        assert name == expected

    def test_index_name_with_zulu_timestamp(self):
        """Test index name generation with Z-suffix timestamp."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = None
        adapter.host = "localhost"
        adapter.port = 9200
        adapter.use_ssl = False
        adapter.verify_certs = False
        adapter.index_prefix = "ulpf"

        name = adapter._get_index_name("2026-09-07T08:01:17Z")

        assert name == "ulpf-events-2026.09.07"


class TestDocumentBuilding:
    """Tests for document construction from NormalizedEvent."""

    def test_build_document_complete(self):
        """Test that complete document is built with all fields."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = None

        event = NormalizedEvent(
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
                "device": {"name": "fw-1", "type": "firewall"},
            },
            parsed_fields={
                "custom_field": "preserve",
                "original_action": "ACCEPT",
            },
            raw_payload="<58>Sep 07 08:01:17 original",
        )

        doc = adapter._build_document(event)

        assert doc["event_id"] == "evt-123"
        assert doc["raw_event_id"] == "raw-456"
        assert doc["source_id"] == "fw-1"
        assert doc["event_action"] == "allow"
        assert doc["event_severity"] == "high"
        assert doc["source_ip"] == "10.0.0.1"
        assert doc["source_port"] == 12345
        assert doc["destination_ip"] == "192.168.1.1"
        assert doc["destination_port"] == 80
        assert doc["network_protocol"] == "TCP"
        assert doc["device_name"] == "fw-1"
        assert doc["device_type"] == "firewall"
        assert doc["ocsf"]["event"]["action"] == "allow"
        assert doc["parsed_fields"]["custom_field"] == "preserve"
        assert doc["raw_payload"] == "<58>Sep 07 08:01:17 original"

    def test_build_document_lossless(self):
        """Test that parsed_fields are preserved (lossless storage)."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = None

        event = NormalizedEvent(
            event_id="evt-123",
            raw_event_id="raw-456",
            parsed_fields={
                "firewall_field_1": "value1",
                "firewall_field_2": 123,
                "nested": {"key": "value"},
            },
        )

        doc = adapter._build_document(event)

        assert doc["parsed_fields"]["firewall_field_1"] == "value1"
        assert doc["parsed_fields"]["firewall_field_2"] == 123
        assert doc["parsed_fields"]["nested"]["key"] == "value"


class TestIndexMapping:
    """Tests for OpenSearch index mapping."""

    def test_mapping_structure(self):
        """Test that mapping has correct structure."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = None

        mapping = adapter._get_index_mapping("test-index")

        assert "settings" in mapping
        assert "mappings" in mapping
        assert mapping["settings"]["number_of_shards"] == 1
        assert mapping["settings"]["number_of_replicas"] == 0

    def test_mapping_fields(self):
        """Test that all searchable fields are mapped."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = None

        mapping = adapter._get_index_mapping("test-index")
        properties = mapping["mappings"]["properties"]

        assert "event_id" in properties
        assert "raw_event_id" in properties
        assert "source_id" in properties
        assert "source_type" in properties
        assert "event_action" in properties
        assert "event_severity" in properties
        assert "source_ip" in properties
        assert "destination_ip" in properties
        assert "ocsf" in properties
        assert "parsed_fields" in properties

    def test_parsed_fields_enabled(self):
        """Test that parsed_fields are stored and searchable."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = None

        mapping = adapter._get_index_mapping("test-index")
        parsed_fields_mapping = mapping["mappings"]["properties"]["parsed_fields"]

        assert parsed_fields_mapping["type"] == "object"
        assert parsed_fields_mapping["enabled"] is True


class TestIdempotency:
    """Tests for idempotent indexing."""

    def test_deterministic_document_id(self):
        """Test that event_id is used as document ID."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = MagicMock()
        adapter.host = "localhost"
        adapter.port = 9200
        adapter.use_ssl = False
        adapter.verify_certs = False
        adapter.index_prefix = "ulpf"

        event = NormalizedEvent(
            event_id="evt-123",
            raw_event_id="raw-456",
            ocsf={},
            parsed_fields={},
        )

        adapter.client.indices.exists.return_value = True
        adapter.client.index.return_value = {"result": "created"}

        doc_id = adapter.index_normalized_event(event)

        assert doc_id == "evt-123"

        adapter.client.index.assert_called_once()
        call_kwargs = adapter.client.index.call_args
        assert call_kwargs[1]["id"] == "evt-123"


class TestSearch:
    """Tests for search functionality."""

    def test_search_by_field(self):
        """Test searching by specific field."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = MagicMock()
        adapter.host = "localhost"
        adapter.port = 9200
        adapter.use_ssl = False
        adapter.verify_certs = False
        adapter.index_prefix = "ulpf"

        adapter.client.search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"event_id": "evt-1", "source_ip": "10.0.0.1"}},
                    {"_source": {"event_id": "evt-2", "source_ip": "10.0.0.1"}},
                ]
            }
        }

        import asyncio
        results = adapter.search_by_field("source_ip", "10.0.0.1")

        assert len(results) == 2
        assert results[0]["event_id"] == "evt-1"

        adapter.client.search.assert_called_once()
        call_kwargs = adapter.client.search.call_args
        assert "term" in str(call_kwargs)

    def test_search_by_time_range(self):
        """Test searching by time range."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = MagicMock()
        adapter.host = "localhost"
        adapter.port = 9200
        adapter.use_ssl = False
        adapter.verify_certs = False
        adapter.index_prefix = "ulpf"

        adapter.client.search.return_value = {"hits": {"hits": []}}

        _ = adapter.search_by_time_range(
            "2026-09-07T00:00:00Z",
            "2026-09-07T23:59:59Z",
        )

        adapter.client.search.assert_called_once()


class TestHealthCheck:
    """Tests for health check functionality."""

    def test_health_check_healthy(self):
        """Test health check when OpenSearch is reachable."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = MagicMock()
        adapter.host = "localhost"
        adapter.port = 9200
        adapter.use_ssl = False
        adapter.verify_certs = False
        adapter.index_prefix = "ulpf"

        adapter.client.ping.return_value = True

        result = adapter.health_check()

        assert result is True

    def test_health_check_unhealthy(self):
        """Test health check when OpenSearch is unreachable."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter.__new__(OpenSearchAdapter)
        adapter._client = MagicMock()
        adapter.host = "localhost"
        adapter.port = 9200
        adapter.use_ssl = False
        adapter.verify_certs = False
        adapter.index_prefix = "ulpf"

        adapter.client.ping.side_effect = Exception("Connection refused")

        result = adapter.health_check()

        assert result is False
