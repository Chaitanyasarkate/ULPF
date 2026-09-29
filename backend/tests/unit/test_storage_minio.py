"""Unit tests for MinIO storage adapter."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from ulpf.common.models import EventEnvelope


class TestObjectKeyGeneration:
    """Tests for deterministic object key generation."""

    def test_key_structure(self):
        """Test that object keys follow expected structure."""
        from ulpf.storage.minio_adapter import MinIOAdapter

        adapter = MinIOAdapter.__new__(MinIOAdapter)
        adapter._client = None
        adapter.endpoint = "localhost:9000"
        adapter.access_key = "test"
        adapter.secret_key = "test"
        adapter.bucket = "test-bucket"
        adapter.secure = False

        key = adapter._generate_object_key(
            raw_event_id="abc-123",
            source_type="firewall",
            received_at="2026-09-07T08:01:17+00:00",
        )

        assert key.startswith("raw-events/2026/09/07/firewall/abc-123.json")
        assert "abc-123" in key

    def test_key_with_empty_source_type(self):
        """Test key generation with empty source type."""
        from ulpf.storage.minio_adapter import MinIOAdapter

        adapter = MinIOAdapter.__new__(MinIOAdapter)
        adapter._client = None

        key = adapter._generate_object_key(
            raw_event_id="abc-123",
            source_type="",
            received_at="2026-09-07T08:01:17+00:00",
        )

        assert "unknown" in key
        assert "abc-123" in key

    def test_key_deterministic(self):
        """Test that same inputs produce same key."""
        from ulpf.storage.minio_adapter import MinIOAdapter

        adapter = MinIOAdapter.__new__(MinIOAdapter)
        adapter._client = None

        key1 = adapter._generate_object_key(
            raw_event_id="abc-123",
            source_type="firewall",
            received_at="2026-09-07T08:01:17+00:00",
        )

        key2 = adapter._generate_object_key(
            raw_event_id="abc-123",
            source_type="firewall",
            received_at="2026-09-07T08:01:17+00:00",
        )

        assert key1 == key2


class TestObjectMetadata:
    """Tests for object metadata building."""

    def test_build_object_content(self):
        """Test that object content contains original payload."""
        from ulpf.storage.minio_adapter import MinIOAdapter

        adapter = MinIOAdapter.__new__(MinIOAdapter)
        adapter._client = None

        envelope = EventEnvelope.from_raw(
            payload="<58>Sep 07 08:01:17 fw-dmz-01 test",
            source_id="fw-dmz-01",
            source_type="firewall",
            fmt="syslog",
        )
        envelope.sha256 = "abc123def456"

        content = adapter._build_object_content(envelope)
        data = json.loads(content.decode("utf-8"))

        assert data["payload"] == "<58>Sep 07 08:01:17 fw-dmz-01 test"
        assert data["raw_event_id"] == envelope.raw.raw_event_id
        assert data["sha256"] == "abc123def456"
        assert data["source_type"] == "firewall"

    def test_build_object_metadata(self):
        """Test that metadata is correctly built."""
        from ulpf.storage.minio_adapter import MinIOAdapter

        adapter = MinIOAdapter.__new__(MinIOAdapter)
        adapter._client = None

        envelope = EventEnvelope.from_raw(
            payload="test",
            source_id="fw-1",
            source_type="firewall",
            fmt="syslog",
        )
        envelope.sha256 = "sha256value"

        metadata = adapter._build_object_metadata(
            envelope,
            object_key="raw-events/2026/09/07/firewall/test.json",
        )

        assert metadata["raw_event_id"] == envelope.raw.raw_event_id
        assert metadata["sha256"] == "sha256value"
        assert metadata["source_type"] == "firewall"


class TestIdempotency:
    """Tests for idempotent storage operations."""

    def test_key_is_deterministic_for_same_id(self):
        """Test that same raw_event_id produces same key."""
        from ulpf.storage.minio_adapter import MinIOAdapter

        adapter = MinIOAdapter.__new__(MinIOAdapter)
        adapter._client = None

        key1 = adapter._generate_object_key(
            "fixed-id-123",
            "firewall",
            "2026-09-07T08:01:17+00:00",
        )

        key2 = adapter._generate_object_key(
            "fixed-id-123",
            "firewall",
            "2026-09-07T08:01:17+00:00",
        )

        assert key1 == key2


class TestIntegrityVerification:
    """Tests for SHA-256 integrity verification."""

    def test_verify_integrity_returns_tuple(self):
        """Test that verify_integrity returns a tuple."""
        from ulpf.storage.minio_adapter import MinIOAdapter

        adapter = MinIOAdapter.__new__(MinIOAdapter)
        adapter._client = MagicMock()
        adapter.endpoint = "localhost:9000"
        adapter.access_key = "test"
        adapter.secret_key = "test"
        adapter.bucket = "test-bucket"
        adapter.secure = False

        adapter.client.list_objects.return_value = iter([])

        import asyncio
        result = asyncio.run(
            adapter.verify_integrity("test-id", "any-hash")
        )

        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_verify_integrity_not_found_returns_false(self):
        """Test integrity verification when object not found."""
        from ulpf.storage.minio_adapter import MinIOAdapter

        adapter = MinIOAdapter.__new__(MinIOAdapter)
        adapter._client = MagicMock()
        adapter.endpoint = "localhost:9000"
        adapter.access_key = "test"
        adapter.secret_key = "test"
        adapter.bucket = "test-bucket"
        adapter.secure = False

        adapter.client.list_objects.return_value = iter([])

        import asyncio
        verified, actual = asyncio.run(
            adapter.verify_integrity("nonexistent", "any-hash")
        )

        assert verified is False
        assert actual is None


class TestHealthCheck:
    """Tests for health check functionality."""

    def test_health_check_returns_bool(self):
        """Test health check returns a boolean."""
        from ulpf.storage.minio_adapter import MinIOAdapter

        adapter = MinIOAdapter.__new__(MinIOAdapter)
        adapter._client = MagicMock()
        adapter.endpoint = "localhost:9000"
        adapter.access_key = "test"
        adapter.secret_key = "test"
        adapter.bucket = "test-bucket"
        adapter.secure = False

        adapter.client.bucket_exists.return_value = True

        import asyncio
        result = asyncio.run(adapter.health_check())

        assert isinstance(result, bool)


class TestUploadEnvelope:
    """Tests for upload envelope functionality."""

    def test_upload_returns_string_key(self):
        """Test that upload returns a string object key."""
        from ulpf.storage.minio_adapter import MinIOAdapter

        adapter = MinIOAdapter.__new__(MinIOAdapter)
        adapter._client = MagicMock()
        adapter.endpoint = "localhost:9000"
        adapter.access_key = "test"
        adapter.secret_key = "test"
        adapter.bucket = "test-bucket"
        adapter.secure = False

        adapter.client.bucket_exists.return_value = True
        adapter.client.list_objects.return_value = iter([])

        envelope = EventEnvelope.from_raw(
            payload="test",
            source_id="fw-1",
            source_type="firewall",
            fmt="syslog",
        )
        envelope.sha256 = "test-hash"

        import asyncio
        result = asyncio.run(adapter.upload_envelope(envelope))

        assert isinstance(result, str)
        assert "raw-events" in result


class TestExists:
    """Tests for exists functionality."""

    def test_exists_returns_bool(self):
        """Test that exists returns a boolean."""
        from ulpf.storage.minio_adapter import MinIOAdapter

        adapter = MinIOAdapter.__new__(MinIOAdapter)
        adapter._client = MagicMock()
        adapter.endpoint = "localhost:9000"
        adapter.access_key = "test"
        adapter.secret_key = "test"
        adapter.bucket = "test-bucket"
        adapter.secure = False

        adapter.client.list_objects.return_value = iter([])

        import asyncio
        result = asyncio.run(adapter.exists("test-id"))

        assert isinstance(result, bool)
