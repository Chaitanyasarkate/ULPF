"""Unit tests for lineage service."""

from __future__ import annotations

from unittest.mock import MagicMock

from ulpf.lineage.models import (
    LineageRecord,
    RelationshipType,
)


class TestLineageService:
    """Tests for LineageService."""

    def test_get_lineage_chain(self):
        from ulpf.lineage.service import LineageService

        mock_repo = MagicMock()
        mock_minio = MagicMock()
        mock_opensearch = MagicMock()

        ancestors = [
            LineageRecord(
                parent_event_id="raw-123",
                child_event_id="parsed-456",
                relationship_type=RelationshipType.PARSED_FROM,
                raw_event_id="raw-123",
            )
        ]

        descendants = [
            LineageRecord(
                parent_event_id="parsed-456",
                child_event_id="norm-789",
                relationship_type=RelationshipType.NORMALIZED_FROM,
                raw_event_id="raw-123",
            )
        ]

        mock_repo.get_ancestors.return_value = ancestors
        mock_repo.get_descendants.return_value = descendants
        mock_opensearch.get_event.return_value = None

        service = LineageService(
            lineage_repository=mock_repo,
            minio_adapter=mock_minio,
            opensearch_adapter=mock_opensearch,
        )

        chain = service.get_lineage_chain("norm-789")

        assert chain is not None
        assert chain.event_id == "norm-789"
        assert chain.raw_event_id == "raw-123"
        assert len(chain.ancestors) == 1
        assert len(chain.descendants) == 1

    def test_get_lineage_chain_not_found(self):
        from ulpf.lineage.service import LineageService

        mock_repo = MagicMock()
        mock_repo.get_ancestors.return_value = []
        mock_repo.get_descendants.return_value = []

        service = LineageService(
            lineage_repository=mock_repo,
            minio_adapter=MagicMock(),
            opensearch_adapter=MagicMock(),
        )

        chain = service.get_lineage_chain("nonexistent")

        assert chain is None


class TestLineageVerification:
    """Tests for lineage verification."""

    def test_verify_lineage_returns_result(self):
        from ulpf.lineage.service import LineageService

        mock_repo = MagicMock()
        mock_repo.get_ancestors.return_value = []
        mock_repo.get_descendants.return_value = []

        mock_minio = MagicMock()
        mock_minio.health_check.return_value = False

        mock_opensearch = MagicMock()
        mock_opensearch.get_event.return_value = None
        mock_opensearch.health_check.return_value = True

        service = LineageService(
            lineage_repository=mock_repo,
            minio_adapter=mock_minio,
            opensearch_adapter=mock_opensearch,
        )

        verification = service.verify_lineage("test-event")

        assert verification is not None
        assert verification.event_id == "test-event"


class TestRawEventRecovery:
    """Tests for raw event recovery."""

    def test_recover_returns_recovery_object(self):
        from ulpf.lineage.service import LineageService

        mock_repo = MagicMock()
        mock_repo.get_ancestors.return_value = []
        mock_repo.get_descendants.return_value = []

        mock_minio = MagicMock()
        mock_minio.health_check.return_value = False

        mock_opensearch = MagicMock()
        mock_opensearch.health_check.return_value = True

        service = LineageService(
            lineage_repository=mock_repo,
            minio_adapter=mock_minio,
            opensearch_adapter=mock_opensearch,
        )

        recovery = service.recover_raw_event("test-event")

        assert recovery is not None
        assert hasattr(recovery, "exists")
        assert hasattr(recovery, "verified")
        assert hasattr(recovery, "error")


class TestHealthCheck:
    """Tests for health check."""

    def test_health_check_returns_dict(self):
        from ulpf.lineage.service import LineageService

        mock_repo = MagicMock()
        mock_minio = MagicMock()
        mock_minio.health_check.return_value = True

        mock_opensearch = MagicMock()
        mock_opensearch.health_check.return_value = True

        service = LineageService(
            lineage_repository=mock_repo,
            minio_adapter=mock_minio,
            opensearch_adapter=mock_opensearch,
        )

        health = service.health_check()

        assert isinstance(health, dict)
        assert "minio" in health
        assert "opensearch" in health
        assert "lineage_repository" in health