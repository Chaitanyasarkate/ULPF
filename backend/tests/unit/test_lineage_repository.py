"""Unit tests for lineage repository."""

from __future__ import annotations

from unittest.mock import MagicMock

from ulpf.lineage.models import LineageRecord, RelationshipType


class TestLineageSchema:
    """Tests for lineage schema SQL."""

    def test_schema_creates_table(self):
        from ulpf.lineage.repository import LINEAGE_SCHEMA_SQL

        assert "CREATE TABLE IF NOT EXISTS event_lineage" in LINEAGE_SCHEMA_SQL

    def test_schema_has_unique_constraint(self):
        from ulpf.lineage.repository import LINEAGE_SCHEMA_SQL

        assert "UNIQUE" in LINEAGE_SCHEMA_SQL
        assert "parent_event_id" in LINEAGE_SCHEMA_SQL
        assert "child_event_id" in LINEAGE_SCHEMA_SQL
        assert "relationship_type" in LINEAGE_SCHEMA_SQL

    def test_schema_has_indexes(self):
        from ulpf.lineage.repository import LINEAGE_SCHEMA_SQL

        assert "CREATE INDEX" in LINEAGE_SCHEMA_SQL
        assert "idx_lineage_parent" in LINEAGE_SCHEMA_SQL
        assert "idx_lineage_child" in LINEAGE_SCHEMA_SQL
        assert "idx_lineage_raw" in LINEAGE_SCHEMA_SQL


class TestLineageRepository:
    """Tests for LineageRepository."""

    def test_record_lineage_builds_query(self):
        from ulpf.lineage.repository import LineageRepository

        mock_pg = MagicMock()
        repo = LineageRepository(connection_provider=mock_pg)

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_pg.get_connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)

        repo.record_lineage(
            parent_event_id="raw-123",
            child_event_id="parsed-456",
            relationship_type=RelationshipType.PARSED_FROM,
            raw_event_id="raw-123",
        )

        mock_cursor.execute.assert_called()
        call_args = mock_cursor.execute.call_args[0]
        query = call_args[0]
        assert "INSERT INTO event_lineage" in query
        assert "ON CONFLICT" in query

    def test_get_ancestors_query(self):
        from ulpf.lineage.repository import LineageRepository

        mock_pg = MagicMock()
        repo = LineageRepository(connection_provider=mock_pg)

        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_pg.get_cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)

        repo.get_ancestors("event-123")

        mock_cursor.execute.assert_called()
        call_args = mock_cursor.execute.call_args[0]
        query = call_args[0]
        assert "child_event_id" in query
        assert "event_lineage" in query

    def test_get_descendants_query(self):
        from ulpf.lineage.repository import LineageRepository

        mock_pg = MagicMock()
        repo = LineageRepository(connection_provider=mock_pg)

        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_pg.get_cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)

        repo.get_descendants("event-123")

        mock_cursor.execute.assert_called()
        call_args = mock_cursor.execute.call_args[0]
        query = call_args[0]
        assert "parent_event_id" in query

    def test_get_lineage_by_raw_id(self):
        from ulpf.lineage.repository import LineageRepository

        mock_pg = MagicMock()
        repo = LineageRepository(connection_provider=mock_pg)

        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_pg.get_cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)

        repo.get_lineage_by_raw_id("raw-123")

        mock_cursor.execute.assert_called()
        call_args = mock_cursor.execute.call_args[0]
        query = call_args[0]
        assert "raw_event_id" in query

    def test_lineage_exists(self):
        from ulpf.lineage.repository import LineageRepository

        mock_pg = MagicMock()
        repo = LineageRepository(connection_provider=mock_pg)

        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)
        mock_pg.get_cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)

        result = repo.lineage_exists(
            "raw-123",
            "parsed-456",
            RelationshipType.PARSED_FROM,
        )

        assert result is True
        mock_cursor.execute.assert_called()


class TestLineageRelationshipTypes:
    """Tests for lineage relationship handling."""

    def test_parsed_from_relationship(self):
        record = LineageRecord(
            parent_event_id="raw-abc",
            child_event_id="parsed-def",
            relationship_type=RelationshipType.PARSED_FROM,
            raw_event_id="raw-abc",
        )

        assert record.relationship_type == RelationshipType.PARSED_FROM
        assert "parsed_from" in record.to_dict()["relationship_type"]

    def test_normalized_from_relationship(self):
        record = LineageRecord(
            parent_event_id="parsed-def",
            child_event_id="norm-ghi",
            relationship_type=RelationshipType.NORMALIZED_FROM,
            raw_event_id="raw-abc",
        )

        assert record.relationship_type == RelationshipType.NORMALIZED_FROM
        assert "normalized_from" in record.to_dict()["relationship_type"]


class TestIdempotency:
    """Tests for idempotent lineage operations."""

    def test_duplicate_lineage_handled(self):
        from ulpf.lineage.repository import LineageRepository

        mock_pg = MagicMock()
        repo = LineageRepository(connection_provider=mock_pg)

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_pg.get_connection.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)

        result = repo.record_lineage(
            parent_event_id="raw-123",
            child_event_id="parsed-456",
            relationship_type=RelationshipType.PARSED_FROM,
            raw_event_id="raw-123",
        )

        assert result is True
        call_args = mock_cursor.execute.call_args[0]
        query = call_args[0]
        assert "ON CONFLICT" in query
        assert "DO NOTHING" in query