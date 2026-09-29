"""Unit tests for schema drift detector."""

from __future__ import annotations

from unittest.mock import MagicMock

from ulpf.schema.detector import SchemaDriftDetector
from ulpf.schema.models import SchemaProfile


class TestSchemaDriftDetector:
    def test_detect_no_drift(self):
        schema = SchemaProfile(
            source_id="firewall.test",
            schema_version="1.0.0",
            required_fields=["src_ip", "dst_ip", "action"],
            optional_fields=["protocol"],
            field_types={
                "src_ip": "string",
                "dst_ip": "string",
                "action": "string",
                "protocol": "string",
            },
        )

        mock_repo = MagicMock()
        mock_repo.get_by_source_id.return_value = schema

        detector = SchemaDriftDetector(schema_repository=mock_repo)

        mock_envelope = MagicMock()
        mock_envelope.parsed = MagicMock()
        mock_envelope.parsed.source_id = "firewall.test"
        mock_envelope.parsed.event_id = "evt-123"
        mock_envelope.parsed.extracted = {
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
            "action": "allow",
            "protocol": "TCP",
        }

        result = detector.detect_drift(mock_envelope)

        assert result is not None
        assert result.drift_detected is False
        assert len(result.drift_types) == 0

    def test_detect_new_field(self):
        schema = SchemaProfile(
            source_id="firewall.test",
            schema_version="1.0.0",
            required_fields=["src_ip", "dst_ip"],
            optional_fields=[],
        )

        mock_repo = MagicMock()
        mock_repo.get_by_source_id.return_value = schema

        detector = SchemaDriftDetector(schema_repository=mock_repo)

        mock_envelope = MagicMock()
        mock_envelope.parsed = MagicMock()
        mock_envelope.parsed.source_id = "firewall.test"
        mock_envelope.parsed.event_id = "evt-123"
        mock_envelope.parsed.extracted = {
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
            "threat_score": "high",
        }

        result = detector.detect_drift(mock_envelope)

        assert result is not None
        assert result.drift_detected is True
        assert "threat_score" in result.new_fields
        assert "new_field" in result.drift_types

    def test_detect_missing_required_field(self):
        schema = SchemaProfile(
            source_id="firewall.test",
            schema_version="1.0.0",
            required_fields=["src_ip", "dst_ip", "action"],
            optional_fields=[],
        )

        mock_repo = MagicMock()
        mock_repo.get_by_source_id.return_value = schema

        detector = SchemaDriftDetector(schema_repository=mock_repo)

        mock_envelope = MagicMock()
        mock_envelope.parsed = MagicMock()
        mock_envelope.parsed.source_id = "firewall.test"
        mock_envelope.parsed.event_id = "evt-123"
        mock_envelope.parsed.extracted = {
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
        }

        result = detector.detect_drift(mock_envelope)

        assert result is not None
        assert result.drift_detected is True
        assert "action" in result.missing_required_fields
        assert "missing_required_field" in result.drift_types
        assert result.severity == "error"

    def test_detect_type_change(self):
        schema = SchemaProfile(
            source_id="firewall.test",
            schema_version="1.0.0",
            required_fields=["src_ip", "severity"],
            optional_fields=[],
            field_types={
                "src_ip": "string",
                "severity": "integer",
            },
        )

        mock_repo = MagicMock()
        mock_repo.get_by_source_id.return_value = schema

        detector = SchemaDriftDetector(schema_repository=mock_repo)

        mock_envelope = MagicMock()
        mock_envelope.parsed = MagicMock()
        mock_envelope.parsed.source_id = "firewall.test"
        mock_envelope.parsed.event_id = "evt-123"
        mock_envelope.parsed.extracted = {
            "src_ip": "10.0.0.1",
            "severity": "high",
        }

        result = detector.detect_drift(mock_envelope)

        assert result is not None
        assert result.drift_detected is True
        assert len(result.type_changes) == 1
        assert result.type_changes[0]["field"] == "severity"
        assert result.type_changes[0]["expected_type"] == "integer"
        assert result.type_changes[0]["actual_type"] == "string"

    def test_detect_multiple_drift_types(self):
        schema = SchemaProfile(
            source_id="firewall.test",
            schema_version="1.0.0",
            required_fields=["src_ip", "action"],
            optional_fields=["protocol"],
            field_types={
                "src_ip": "string",
                "action": "string",
                "protocol": "string",
            },
        )

        mock_repo = MagicMock()
        mock_repo.get_by_source_id.return_value = schema

        detector = SchemaDriftDetector(schema_repository=mock_repo)

        mock_envelope = MagicMock()
        mock_envelope.parsed = MagicMock()
        mock_envelope.parsed.source_id = "firewall.test"
        mock_envelope.parsed.event_id = "evt-123"
        mock_envelope.parsed.extracted = {
            "src_ip": "10.0.0.1",
            "new_field": "value",
        }

        result = detector.detect_drift(mock_envelope)

        assert result is not None
        assert result.drift_detected is True
        assert "new_field" in result.new_fields
        assert "action" in result.missing_required_fields
        assert "protocol" in result.missing_optional_fields
        assert result.severity == "error"

    def test_no_schema_registered(self):
        mock_repo = MagicMock()
        mock_repo.get_by_source_id.return_value = None

        detector = SchemaDriftDetector(schema_repository=mock_repo)

        mock_envelope = MagicMock()
        mock_envelope.parsed = MagicMock()
        mock_envelope.parsed.source_id = "unknown.source"
        mock_envelope.parsed.event_id = "evt-123"
        mock_envelope.parsed.extracted = {"field": "value"}

        result = detector.detect_drift(mock_envelope)
        assert result is None

    def test_no_parsed_event(self):
        mock_repo = MagicMock()
        detector = SchemaDriftDetector(schema_repository=mock_repo)

        mock_envelope = MagicMock()
        mock_envelope.parsed = None

        result = detector.detect_drift(mock_envelope)
        assert result is None

    def test_register_schema(self):
        mock_repo = MagicMock()

        detector = SchemaDriftDetector(schema_repository=mock_repo)

        schema = SchemaProfile(
            source_id="firewall.new",
            schema_version="1.0.0",
            required_fields=["src_ip"],
        )

        mock_repo.upsert.return_value = schema

        result = detector.register_schema(schema)

        assert result.source_id == "firewall.new"
        mock_repo.upsert.assert_called_once()

    def test_get_schema_caches(self):
        schema = SchemaProfile(
            source_id="firewall.cached",
            schema_version="1.0.0",
            required_fields=["src_ip"],
        )

        mock_repo = MagicMock()
        mock_repo.get_by_source_id.return_value = schema

        detector = SchemaDriftDetector(schema_repository=mock_repo)

        result1 = detector.get_schema("firewall.cached")
        result2 = detector.get_schema("firewall.cached")

        assert result1 == result2
        assert result1.source_id == "firewall.cached"
        mock_repo.get_by_source_id.assert_called_once()

    def test_list_schemas(self):
        schemas = [
            SchemaProfile(source_id="firewall.fw-1", schema_version="1.0.0", required_fields=[]),
            SchemaProfile(source_id="firewall.fw-2", schema_version="1.0.0", required_fields=[]),
            SchemaProfile(source_id="router.r1", schema_version="1.0.0", required_fields=[]),
        ]

        mock_repo = MagicMock()
        mock_repo.list_all.return_value = schemas

        detector = SchemaDriftDetector(schema_repository=mock_repo)

        all_schemas = detector.list_schemas()
        assert len(all_schemas) == 3

        firewall_only = detector.list_schemas(source_type="firewall")
        assert len(firewall_only) == 2


class TestTypeInference:
    def test_infer_types(self):
        from ulpf.schema.detector import SchemaDriftDetector

        assert SchemaDriftDetector._infer_type(None) == "null"
        assert SchemaDriftDetector._infer_type(True) == "boolean"
        assert SchemaDriftDetector._infer_type(123) == "integer"
        assert SchemaDriftDetector._infer_type(3.14) == "float"
        assert SchemaDriftDetector._infer_type("string") == "string"
        assert SchemaDriftDetector._infer_type({"key": "value"}) == "object"
        assert SchemaDriftDetector._infer_type([1, 2, 3]) == "array"
