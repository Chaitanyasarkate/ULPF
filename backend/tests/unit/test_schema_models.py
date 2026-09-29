"""Unit tests for schema models."""

from __future__ import annotations

from ulpf.schema.models import (
    DriftDetectionResult,
    DriftEvent,
    DriftSeverity,
    DriftType,
    SchemaProfile,
)


class TestSchemaProfile:
    def test_create_schema(self):
        schema = SchemaProfile(
            source_id="firewall.paloalto",
            schema_version="1.0.0",
            required_fields=["src_ip", "dst_ip", "action"],
            optional_fields=["src_port", "dst_port", "protocol"],
            field_types={
                "src_ip": "string",
                "dst_ip": "string",
                "action": "string",
                "src_port": "integer",
            },
        )

        assert schema.source_id == "firewall.paloalto"
        assert schema.schema_version == "1.0.0"
        assert len(schema.required_fields) == 3
        assert len(schema.optional_fields) == 3
        assert schema.active is True

    def test_get_all_fields(self):
        schema = SchemaProfile(
            source_id="test",
            schema_version="1.0.0",
            required_fields=["a", "b"],
            optional_fields=["c", "d"],
        )

        all_fields = schema.get_all_fields()
        assert all_fields == {"a", "b", "c", "d"}

    def test_is_required(self):
        schema = SchemaProfile(
            source_id="test",
            schema_version="1.0.0",
            required_fields=["src_ip", "action"],
            optional_fields=["src_port"],
        )

        assert schema.is_required("src_ip") is True
        assert schema.is_required("action") is True
        assert schema.is_required("src_port") is False

    def test_is_optional(self):
        schema = SchemaProfile(
            source_id="test",
            schema_version="1.0.0",
            required_fields=["src_ip"],
            optional_fields=["src_port", "protocol"],
        )

        assert schema.is_optional("src_port") is True
        assert schema.is_optional("src_ip") is False

    def test_get_expected_type(self):
        schema = SchemaProfile(
            source_id="test",
            schema_version="1.0.0",
            field_types={
                "src_ip": "string",
                "src_port": "integer",
                "bytes": "float",
            },
        )

        assert schema.get_expected_type("src_ip") == "string"
        assert schema.get_expected_type("src_port") == "integer"
        assert schema.get_expected_type("bytes") == "float"
        assert schema.get_expected_type("unknown") is None

    def test_to_dict(self):
        schema = SchemaProfile(
            source_id="firewall.test",
            schema_version="1.0.0",
            required_fields=["src_ip"],
            optional_fields=["dst_ip"],
            description="Test schema",
        )

        data = schema.to_dict()
        assert data["source_id"] == "firewall.test"
        assert data["schema_version"] == "1.0.0"
        assert data["required_fields"] == ["src_ip"]
        assert data["optional_fields"] == ["dst_ip"]
        assert data["description"] == "Test schema"

    def test_from_dict(self):
        data = {
            "source_id": "router.cisco",
            "schema_version": "2.0.0",
            "required_fields": ["src_ip", "dst_ip"],
            "optional_fields": ["vlan"],
            "field_types": {"src_ip": "string", "vlan": "integer"},
            "active": True,
        }

        schema = SchemaProfile.from_dict(data)
        assert schema.source_id == "router.cisco"
        assert schema.schema_version == "2.0.0"
        assert "src_ip" in schema.required_fields
        assert schema.field_types["vlan"] == "integer"


class TestDriftDetectionResult:
    def test_no_drift(self):
        result = DriftDetectionResult(
            source_id="test",
            schema_version="1.0.0",
            event_id="evt-123",
        )

        assert result.drift_detected is False
        assert len(result.drift_types) == 0

    def test_add_new_field(self):
        result = DriftDetectionResult(
            source_id="test",
            schema_version="1.0.0",
            event_id="evt-123",
        )

        result.add_new_field("threat_score")
        assert result.drift_detected is True
        assert "threat_score" in result.new_fields
        assert DriftType.NEW_FIELD.value in result.drift_types
        assert result.severity == DriftSeverity.INFO.value

    def test_add_missing_required_field(self):
        result = DriftDetectionResult(
            source_id="test",
            schema_version="1.0.0",
            event_id="evt-123",
        )

        result.add_missing_required_field("action")
        assert result.drift_detected is True
        assert "action" in result.missing_required_fields
        assert DriftType.MISSING_REQUIRED_FIELD.value in result.drift_types
        assert result.severity == DriftSeverity.ERROR.value

    def test_add_missing_optional_field(self):
        result = DriftDetectionResult(
            source_id="test",
            schema_version="1.0.0",
            event_id="evt-123",
        )

        result.add_missing_optional_field("protocol")
        assert result.drift_detected is True
        assert "protocol" in result.missing_optional_fields
        assert result.severity == DriftSeverity.INFO.value

    def test_add_type_change(self):
        result = DriftDetectionResult(
            source_id="test",
            schema_version="1.0.0",
            event_id="evt-123",
        )

        result.add_type_change("severity", "integer", "string")
        assert result.drift_detected is True
        assert len(result.type_changes) == 1
        assert result.type_changes[0]["field"] == "severity"
        assert result.type_changes[0]["expected_type"] == "integer"
        assert result.type_changes[0]["actual_type"] == "string"
        assert result.severity == DriftSeverity.WARNING.value

    def test_severity_escalation(self):
        result = DriftDetectionResult(
            source_id="test",
            schema_version="1.0.0",
            event_id="evt-123",
        )

        result.add_new_field("extra_field")
        assert result.severity == DriftSeverity.INFO.value

        result.add_type_change("field", "int", "str")
        assert result.severity == DriftSeverity.WARNING.value

        result.add_missing_required_field("critical_field")
        assert result.severity == DriftSeverity.ERROR.value

    def test_to_dict(self):
        result = DriftDetectionResult(
            source_id="firewall.test",
            schema_version="1.0.0",
            event_id="evt-456",
            drift_detected=True,
            new_fields=["threat_score"],
            missing_required_fields=["action"],
            severity=DriftSeverity.WARNING.value,
        )

        data = result.to_dict()
        assert data["source_id"] == "firewall.test"
        assert data["event_id"] == "evt-456"
        assert data["drift_detected"] is True
        assert "threat_score" in data["new_fields"]
        assert "action" in data["missing_required_fields"]


class TestDriftEvent:
    def test_create_drift_event(self):
        event = DriftEvent(
            drift_id="drift-evt-123",
            event_id="evt-123",
            raw_event_id="raw-456",
            source_id="firewall.test",
            schema_version="1.0.0",
            drift_types=["new_field"],
            new_fields=["threat_score"],
            missing_fields=[],
            type_changes=[],
            severity="info",
        )

        assert event.drift_id == "drift-evt-123"
        assert event.event_id == "evt-123"
        assert event.source_id == "firewall.test"
        assert "threat_score" in event.new_fields

    def test_to_dict(self):
        event = DriftEvent(
            drift_id="drift-evt-789",
            event_id="evt-789",
            raw_event_id="raw-000",
            source_id="router.test",
            schema_version="1.0.0",
            drift_types=["new_field", "type_change"],
            new_fields=["vlan_id"],
            missing_fields=[],
            type_changes=[{"field": "port", "expected": "int", "actual": "str"}],
            severity="warning",
        )

        data = event.to_dict()
        assert data["drift_id"] == "drift-evt-789"
        assert data["event_id"] == "evt-789"
        assert data["source_id"] == "router.test"
        assert "vlan_id" in data["new_fields"]
        assert data["severity"] == "warning"


class TestDriftSeverity:
    def test_values(self):
        values = DriftSeverity.values()
        assert "info" in values
        assert "warning" in values
        assert "error" in values


class TestDriftType:
    def test_values(self):
        values = DriftType.values()
        assert "new_field" in values
        assert "missing_required_field" in values
        assert "type_change" in values
