"""Integration tests for ULPF Phase 6 lineage layer.

These tests require Docker services to be running.
Set ULPF_INTEGRATION=1 to enable.

Prerequisites:
    docker compose up -d  # Start MinIO, OpenSearch, PostgreSQL
"""

from __future__ import annotations

import os

import pytest

from ulpf.common.models import EventEnvelope, NormalizedEvent
from ulpf.lineage.repository import LineageRepository
from ulpf.lineage.service import LineageService

pytestmark = pytest.mark.skipif(
    os.environ.get("ULPF_INTEGRATION") != "1",
    reason="ULPF_INTEGRATION not set; requires Docker services",
)


class TestLineageIntegration:
    """Integration tests for lineage layer."""

    @pytest.fixture
    def repository(self):
        return LineageRepository()

    @pytest.fixture
    def service(self):
        return LineageService()

    @pytest.fixture
    def sample_envelope(self):
        envelope = EventEnvelope.from_raw(
            payload="<58>Sep 07 08:01:17 fw-dmz-01 test",
            source_id="fw-dmz-01",
            source_type="firewall",
            fmt="syslog",
        )
        envelope.sha256 = "test-sha256"
        envelope.parser_id = "firewall_syslog_v1"
        envelope.parser_version = "1.0.0"
        return envelope

    def test_schema_initialization(self, repository):
        import asyncio
        asyncio.run(repository.initialize_schema())

    def test_record_parsed_lineage(self, repository, sample_envelope):
        import asyncio

        asyncio.run(repository.initialize_schema())

        from ulpf.common.models import ParsedEvent
        sample_envelope.parsed = ParsedEvent(
            event_id="parsed-123",
            raw_event_id=sample_envelope.raw.raw_event_id,
            source_id="fw-dmz-01",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
            parser_version="1.0.0",
            extracted={"action": "accept"},
        )

        result = asyncio.run(repository.record_parsed_lineage(sample_envelope))
        assert result is True

    def test_get_ancestors(self, repository, sample_envelope):
        import asyncio

        asyncio.run(repository.initialize_schema())

        from ulpf.common.models import ParsedEvent
        sample_envelope.parsed = ParsedEvent(
            event_id="parsed-456",
            raw_event_id=sample_envelope.raw.raw_event_id,
            source_id="fw-dmz-01",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
            parser_version="1.0.0",
            extracted={},
        )

        asyncio.run(repository.record_parsed_lineage(sample_envelope))

        ancestors = asyncio.run(repository.get_ancestors("parsed-456"))
        assert len(ancestors) >= 1

    def test_get_lineage_chain(self, service):
        import asyncio

        asyncio.run(service.initialize())

        envelope = EventEnvelope.from_raw(
            payload="test",
            source_id="fw-1",
            source_type="firewall",
            fmt="syslog",
        )
        envelope.sha256 = "chain-test-sha256"

        from ulpf.common.models import ParsedEvent
        envelope.parsed = ParsedEvent(
            event_id="chain-parsed-001",
            raw_event_id=envelope.raw.raw_event_id,
            source_id="fw-1",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
            parser_version="1.0.0",
            extracted={},
        )

        import asyncio
        asyncio.run(service.record_parsing_lineage(envelope))

        chain = asyncio.run(service.get_lineage_chain("chain-parsed-001"))
        assert chain is not None


class TestLineageCompleteChain:
    """End-to-end lineage chain tests."""

    @pytest.fixture
    def service(self):
        return LineageService()

    def test_complete_raw_to_normalized_chain(self, service):
        import asyncio

        asyncio.run(service.initialize())

        envelope = EventEnvelope.from_raw(
            payload="<58>Sep 07 08:01:17 complete-chain-test",
            source_id="fw-complete",
            source_type="firewall",
            fmt="syslog",
        )
        envelope.sha256 = "complete-chain-sha256"
        envelope.parser_id = "firewall_syslog_v1"
        envelope.parser_version = "1.0.0"

        from ulpf.common.models import ParsedEvent
        envelope.parsed = ParsedEvent(
            event_id="complete-parsed-001",
            raw_event_id=envelope.raw.raw_event_id,
            source_id="fw-complete",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
            parser_version="1.0.0",
            extracted={"action": "accept"},
            event_timestamp="2026-09-07T08:01:17+00:00",
        )

        envelope.normalized = NormalizedEvent(
            event_id="complete-norm-001",
            raw_event_id=envelope.raw.raw_event_id,
            source_id="fw-complete",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
            parser_version="1.0.0",
            schema_version="1.0.0",
            event_timestamp="2026-09-07T08:01:17+00:00",
            sha256="complete-chain-sha256",
            ocsf={"event": {"action": "allow"}},
            parsed_fields={"action": "accept"},
            raw_payload=envelope.raw.payload,
        )

        asyncio.run(service.record_parsing_lineage(envelope))
        asyncio.run(service.record_normalization_lineage(envelope))

        chain = asyncio.run(service.get_lineage_chain("complete-norm-001"))
        assert chain is not None
        assert chain.raw_event_id == envelope.raw.raw_event_id
        assert len(chain.ancestors) >= 1


class TestLineageVerificationIntegration:
    """Tests for lineage verification."""

    @pytest.fixture
    def service(self):
        return LineageService()

    def test_verify_with_missing_raw(self, service):
        import asyncio

        asyncio.run(service.initialize())

        verification = asyncio.run(service.verify_lineage("nonexistent-event"))

        assert verification.status.value in ["invalid", "unavailable"]
        assert verification.raw_object_exists is False
