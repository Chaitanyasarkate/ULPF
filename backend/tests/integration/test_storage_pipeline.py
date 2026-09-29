"""Integration tests for ULPF Phase 5 storage layer.

These tests require Docker services to be running.
Set ULPF_INTEGRATION=1 to enable.

Prerequisites:
    docker compose up -d  # Start MinIO, OpenSearch, PostgreSQL
"""

from __future__ import annotations

import os

import pytest

from ulpf.common.models import EventEnvelope, NormalizedEvent
from ulpf.storage.minio_adapter import MinIOAdapter
from ulpf.storage.opensearch_adapter import OpenSearchAdapter
from ulpf.storage.postgres_adapter import PostgresAdapter

pytestmark = pytest.mark.skipif(
    os.environ.get("ULPF_INTEGRATION") != "1",
    reason="ULPF_INTEGRATION not set; requires Docker services",
)


class TestMinIOIntegration:
    """Integration tests for MinIO storage."""

    @pytest.fixture
    def adapter(self):
        return MinIOAdapter()

    @pytest.fixture
    def sample_envelope(self):
        envelope = EventEnvelope.from_raw(
            payload="<58>Sep 07 08:01:17 fw-dmz-01 %ASA-6-302013: ACCEPT inbound TCP src=10.103.83.13:12345 dst=192.168.1.10:80",
            source_id="fw-dmz-01",
            source_type="firewall",
            fmt="syslog",
        )
        envelope.sha256 = "abc123def456789"
        return envelope

    def test_bucket_exists_or_created(self, adapter):
        import asyncio
        result = asyncio.run(adapter.ensure_bucket_exists())
        assert result is None

    def test_upload_and_retrieve(self, adapter, sample_envelope):
        import asyncio

        asyncio.run(adapter.ensure_bucket_exists())

        key = asyncio.run(adapter.upload_envelope(sample_envelope))
        assert key is not None
        assert "raw-events" in key

        payload = asyncio.run(adapter.get_raw_payload(sample_envelope.raw.raw_event_id))
        assert payload == sample_envelope.raw.payload

    def test_sha256_verification(self, adapter, sample_envelope):
        import asyncio

        asyncio.run(adapter.ensure_bucket_exists())

        asyncio.run(adapter.upload_envelope(sample_envelope))

        verified, actual = asyncio.run(
            adapter.verify_integrity(
                sample_envelope.raw.raw_event_id,
                sample_envelope.sha256,
            )
        )

        assert verified is True
        assert actual == sample_envelope.sha256

    def test_idempotent_upload(self, adapter, sample_envelope):
        import asyncio

        asyncio.run(adapter.ensure_bucket_exists())

        key1 = asyncio.run(adapter.upload_envelope(sample_envelope))
        key2 = asyncio.run(adapter.upload_envelope(sample_envelope))

        assert key1 == key2

    def test_health_check(self, adapter):
        import asyncio
        result = asyncio.run(adapter.health_check())
        assert result is True


class TestOpenSearchIntegration:
    """Integration tests for OpenSearch storage."""

    @pytest.fixture
    def adapter(self):
        return OpenSearchAdapter()

    @pytest.fixture
    def sample_event(self):
        return NormalizedEvent(
            event_id="test-evt-001",
            raw_event_id="test-raw-001",
            source_id="fw-test",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
            parser_version="1.0.0",
            schema_version="1.0.0",
            event_timestamp="2026-09-07T08:01:17+00:00",
            ingestion_timestamp="2026-09-07T08:01:18+00:00",
            sha256="test-sha256",
            ocsf={
                "event": {"action": "allow", "severity": "high"},
                "source": {"ip": "10.0.0.1", "port": 12345},
                "destination": {"ip": "192.168.1.1", "port": 80},
                "network": {"protocol": "TCP"},
                "device": {"name": "fw-test", "type": "firewall"},
            },
            parsed_fields={
                "original_action": "ACCEPT",
                "custom_field": "preserve_me",
            },
            raw_payload="<58>Sep 07 original",
        )

    def test_index_creation(self, adapter):
        index_name = adapter.ensure_index("ulpf-test-index")
        assert index_name == "ulpf-test-index"

    def test_index_and_retrieve(self, adapter, sample_event):
        doc_id = adapter.index_normalized_event(sample_event)
        assert doc_id == sample_event.event_id

        retrieved = adapter.get_event(sample_event.event_id)
        assert retrieved is not None
        assert retrieved["event_id"] == sample_event.event_id
        assert retrieved["source_ip"] == "10.0.0.1"

    def test_search_by_field(self, adapter, sample_event):
        adapter.index_normalized_event(sample_event)

        results = adapter.search_by_field("source_ip", "10.0.0.1")
        assert len(results) >= 1
        assert any(r["event_id"] == sample_event.event_id for r in results)

    def test_lossless_parsed_fields(self, adapter, sample_event):
        adapter.index_normalized_event(sample_event)

        retrieved = adapter.get_event(sample_event.event_id)
        assert retrieved["parsed_fields"]["custom_field"] == "preserve_me"
        assert retrieved["parsed_fields"]["original_action"] == "ACCEPT"

    def test_health_check(self, adapter):
        import asyncio
        result = asyncio.run(adapter.health_check())
        assert result is True


class TestPostgresIntegration:
    """Integration tests for PostgreSQL storage."""

    @pytest.fixture
    def adapter(self):
        adapter = PostgresAdapter()
        return adapter

    @pytest.fixture
    def sample_envelope(self):
        envelope = EventEnvelope.from_raw(
            payload="test payload",
            source_id="fw-test",
            source_type="firewall",
            fmt="syslog",
        )
        envelope.sha256 = "pg-test-sha256"
        envelope.parser_id = "firewall_syslog_v1"
        envelope.parser_version = "1.0.0"
        return envelope

    def test_schema_initialization(self, adapter):
        import asyncio
        asyncio.run(adapter.initialize_schema())

    def test_event_metadata_insert(self, adapter, sample_envelope):
        import asyncio

        asyncio.run(adapter.initialize_schema())

        result = asyncio.run(adapter.insert_event_metadata(sample_envelope, "raw_stored"))
        assert result is True

        retrieved = asyncio.run(adapter.get_event_by_raw_id(sample_envelope.raw.raw_event_id))
        assert retrieved is not None
        assert retrieved["raw_event_id"] == sample_envelope.raw.raw_event_id
        assert retrieved["processing_status"] == "raw_stored"

    def test_raw_object_metadata_insert(self, adapter, sample_envelope):
        import asyncio

        asyncio.run(adapter.initialize_schema())

        asyncio.run(adapter.insert_event_metadata(sample_envelope))

        result = asyncio.run(adapter.insert_raw_object_metadata(
            raw_event_id=sample_envelope.raw.raw_event_id,
            object_key="raw-events/2026/09/07/firewall/test.json",
            bucket="ulpf-raw-events",
            sha256=sample_envelope.sha256,
        ))
        assert result is True

        ref = asyncio.run(adapter.get_raw_object_reference(sample_envelope.raw.raw_event_id))
        assert ref is not None
        assert ref["object_key"] == "raw-events/2026/09/07/firewall/test.json"

    def test_lineage_resolution(self, adapter, sample_envelope):
        import asyncio

        asyncio.run(adapter.initialize_schema())

        asyncio.run(adapter.insert_event_metadata(sample_envelope))

        asyncio.run(adapter.insert_raw_object_metadata(
            raw_event_id=sample_envelope.raw.raw_event_id,
            object_key="raw-events/2026/09/07/firewall/test.json",
            bucket="ulpf-raw-events",
            sha256=sample_envelope.sha256,
        ))

        raw_ref = asyncio.run(adapter.get_raw_object_reference(sample_envelope.raw.raw_event_id))
        assert raw_ref is not None

    def test_health_check(self, adapter):
        import asyncio
        result = asyncio.run(adapter.health_check())
        assert result is True


class TestStoragePipelineIntegration:
    """End-to-end integration tests for storage pipeline."""

    @pytest.fixture
    def minio_adapter(self):
        return MinIOAdapter()

    @pytest.fixture
    def os_adapter(self):
        return OpenSearchAdapter()

    @pytest.fixture
    def pg_adapter(self):
        return PostgresAdapter()

    def test_complete_storage_flow(self, minio_adapter, os_adapter, pg_adapter):
        import asyncio

        asyncio.run(minio_adapter.ensure_bucket_exists())
        asyncio.run(pg_adapter.initialize_schema())

        envelope = EventEnvelope.from_raw(
            payload="<58>Sep 07 08:01:17 complete-flow-test",
            source_id="fw-test",
            source_type="firewall",
            fmt="syslog",
        )
        envelope.sha256 = "complete-flow-sha256"
        envelope.parser_id = "firewall_syslog_v1"
        envelope.parser_version = "1.0.0"

        raw_key = asyncio.run(minio_adapter.upload_envelope(envelope))
        assert raw_key is not None

        asyncio.run(pg_adapter.insert_event_metadata(envelope, "raw_stored"))

        asyncio.run(pg_adapter.insert_raw_object_metadata(
            raw_event_id=envelope.raw.raw_event_id,
            object_key=raw_key,
            bucket=minio_adapter.bucket,
            sha256=envelope.sha256,
        ))

        normalized = NormalizedEvent(
            event_id="norm-evt-001",
            raw_event_id=envelope.raw.raw_event_id,
            source_id=envelope.raw.source_id,
            source_type=envelope.raw.source_type,
            format=envelope.raw.format,
            parser_id=envelope.parser_id,
            parser_version=envelope.parser_version,
            schema_version="1.0.0",
            event_timestamp=envelope.raw.received_at,
            sha256=envelope.sha256,
            ocsf={
                "event": {"action": "allow", "severity": "medium"},
                "source": {"ip": "10.0.0.1"},
                "network": {"protocol": "TCP"},
            },
            parsed_fields={"original": "preserved"},
            raw_payload=envelope.raw.payload,
        )

        norm_index = asyncio.run(os_adapter.index_normalized_event(normalized))
        assert norm_index is not None

        asyncio.run(pg_adapter.insert_normalized_event_metadata(
            normalized,
            index_name=norm_index,
        ))

        raw_ref = asyncio.run(pg_adapter.get_raw_object_reference(envelope.raw.raw_event_id))
        assert raw_ref is not None
        assert raw_ref["sha256"] == envelope.sha256

        verified, _actual = asyncio.run(
            minio_adapter.verify_integrity(envelope.raw.raw_event_id, envelope.sha256)
        )
        assert verified is True
