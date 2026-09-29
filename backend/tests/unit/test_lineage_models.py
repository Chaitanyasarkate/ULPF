"""Unit tests for lineage models."""

from __future__ import annotations

from ulpf.lineage.models import (
    LineageChain,
    LineageRecord,
    LineageVerification,
    RawEventRecovery,
    RelationshipType,
    VerificationStatus,
)


class TestRelationshipType:
    """Tests for RelationshipType enum."""

    def test_parsed_from_value(self):
        assert RelationshipType.PARSED_FROM.value == "parsed_from"

    def test_normalized_from_value(self):
        assert RelationshipType.NORMALIZED_FROM.value == "normalized_from"

    def test_derived_from_value(self):
        assert RelationshipType.DERIVED_FROM.value == "derived_from"


class TestVerificationStatus:
    """Tests for VerificationStatus enum."""

    def test_valid_value(self):
        assert VerificationStatus.VALID.value == "valid"

    def test_invalid_value(self):
        assert VerificationStatus.INVALID.value == "invalid"

    def test_unavailable_value(self):
        assert VerificationStatus.UNAVAILABLE.value == "unavailable"


class TestLineageRecord:
    """Tests for LineageRecord model."""

    def test_creation(self):
        record = LineageRecord(
            parent_event_id="raw-123",
            child_event_id="parsed-456",
            relationship_type=RelationshipType.PARSED_FROM,
            raw_event_id="raw-123",
        )

        assert record.parent_event_id == "raw-123"
        assert record.child_event_id == "parsed-456"
        assert record.relationship_type == RelationshipType.PARSED_FROM
        assert record.raw_event_id == "raw-123"
        assert record.created_at is not None

    def test_to_dict(self):
        record = LineageRecord(
            parent_event_id="raw-123",
            child_event_id="parsed-456",
            relationship_type=RelationshipType.PARSED_FROM,
            raw_event_id="raw-123",
        )

        data = record.to_dict()

        assert data["parent_event_id"] == "raw-123"
        assert data["child_event_id"] == "parsed-456"
        assert data["relationship_type"] == "parsed_from"
        assert data["raw_event_id"] == "raw-123"

    def test_from_dict(self):
        data = {
            "parent_event_id": "raw-123",
            "child_event_id": "parsed-456",
            "relationship_type": "parsed_from",
            "raw_event_id": "raw-123",
        }

        record = LineageRecord.from_dict(data)

        assert record.parent_event_id == "raw-123"
        assert record.child_event_id == "parsed-456"
        assert record.relationship_type == RelationshipType.PARSED_FROM

    def test_with_metadata(self):
        record = LineageRecord(
            parent_event_id="raw-123",
            child_event_id="parsed-456",
            relationship_type=RelationshipType.PARSED_FROM,
            raw_event_id="raw-123",
            metadata={"parser_id": "firewall_v1", "version": "1.0"},
        )

        assert record.metadata["parser_id"] == "firewall_v1"
        assert record.metadata["version"] == "1.0"


class TestLineageChain:
    """Tests for LineageChain model."""

    def test_creation_empty(self):
        chain = LineageChain(
            event_id="norm-789",
            raw_event_id="raw-123",
        )

        assert chain.event_id == "norm-789"
        assert chain.raw_event_id == "raw-123"
        assert chain.ancestors == []
        assert chain.descendants == []

    def test_creation_with_records(self):
        parsed_record = LineageRecord(
            parent_event_id="raw-123",
            child_event_id="parsed-456",
            relationship_type=RelationshipType.PARSED_FROM,
            raw_event_id="raw-123",
        )

        norm_record = LineageRecord(
            parent_event_id="parsed-456",
            child_event_id="norm-789",
            relationship_type=RelationshipType.NORMALIZED_FROM,
            raw_event_id="raw-123",
        )

        chain = LineageChain(
            event_id="norm-789",
            raw_event_id="raw-123",
            ancestors=[parsed_record, norm_record],
            sha256="abc123",
            parser_id="firewall_v1",
        )

        assert len(chain.ancestors) == 2
        assert chain.sha256 == "abc123"
        assert chain.parser_id == "firewall_v1"

    def test_to_dict(self):
        chain = LineageChain(
            event_id="norm-789",
            raw_event_id="raw-123",
            sha256="abc123",
        )

        data = chain.to_dict()

        assert data["event_id"] == "norm-789"
        assert data["raw_event_id"] == "raw-123"
        assert data["sha256"] == "abc123"
        assert data["ancestors"] == []
        assert data["descendants"] == []


class TestLineageVerification:
    """Tests for LineageVerification model."""

    def test_creation_defaults(self):
        verification = LineageVerification(
            event_id="norm-789",
            raw_event_id="raw-123",
        )

        assert verification.event_id == "norm-789"
        assert verification.raw_event_id == "raw-123"
        assert verification.status == VerificationStatus.UNCHECKED
        assert verification.sha256_verified is None
        assert verification.errors == []

    def test_is_valid(self):
        verification = LineageVerification(
            event_id="norm-789",
            raw_event_id="raw-123",
            status=VerificationStatus.VALID,
        )

        assert verification.is_valid is True
        assert verification.is_invalid is False

    def test_is_invalid(self):
        verification = LineageVerification(
            event_id="norm-789",
            raw_event_id="raw-123",
            status=VerificationStatus.INVALID,
        )

        assert verification.is_valid is False
        assert verification.is_invalid is True

    def test_is_unavailable(self):
        verification = LineageVerification(
            event_id="norm-789",
            raw_event_id="raw-123",
            status=VerificationStatus.UNAVAILABLE,
        )

        assert verification.is_unavailable is True

    def test_to_dict(self):
        verification = LineageVerification(
            event_id="norm-789",
            raw_event_id="raw-123",
            status=VerificationStatus.VALID,
            sha256_verified=True,
            raw_object_exists=True,
            normalized_object_exists=True,
            lineage_complete=True,
        )

        data = verification.to_dict()

        assert data["event_id"] == "norm-789"
        assert data["status"] == "valid"
        assert data["sha256_verified"] is True
        assert data["lineage_complete"] is True


class TestRawEventRecovery:
    """Tests for RawEventRecovery model."""

    def test_creation_success(self):
        recovery = RawEventRecovery(
            raw_event_id="raw-123",
            sha256="abc123",
            expected_sha256="abc123",
            raw_payload="<58>Sep 07 original",
            object_key="raw-events/2026/09/07/firewall/raw-123.json",
            bucket="ulpf-raw-events",
            exists=True,
            verified=True,
        )

        assert recovery.exists is True
        assert recovery.verified is True
        assert recovery.raw_payload == "<58>Sep 07 original"

    def test_integrity_ok(self):
        recovery = RawEventRecovery(
            raw_event_id="raw-123",
            sha256="abc123",
            expected_sha256="abc123",
            exists=True,
            verified=True,
        )

        assert recovery.integrity_ok is True

    def test_integrity_failed(self):
        recovery = RawEventRecovery(
            raw_event_id="raw-123",
            sha256="different",
            expected_sha256="abc123",
            exists=True,
            verified=False,
        )

        assert recovery.integrity_ok is False

    def test_integrity_not_exists(self):
        recovery = RawEventRecovery(
            raw_event_id="raw-123",
            sha256="",
            expected_sha256="abc123",
            exists=False,
        )

        assert recovery.integrity_ok is False

    def test_to_dict(self):
        recovery = RawEventRecovery(
            raw_event_id="raw-123",
            sha256="abc123",
            expected_sha256="abc123",
            raw_payload="original",
            exists=True,
            verified=True,
        )

        data = recovery.to_dict()

        assert data["raw_event_id"] == "raw-123"
        assert data["sha256"] == "abc123"
        assert data["raw_payload"] == "original"
        assert data["exists"] is True
        assert data["verified"] is True
