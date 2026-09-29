"""Unit tests for onboarding models."""

from __future__ import annotations

from ulpf.onboarding.models import (
    LogFormat,
    SourceProfile,
    SourceStatus,
    SourceType,
)


class TestSourceProfile:
    def test_create_profile(self):
        profile = SourceProfile(
            source_id="firewall.paloalto",
            source_name="Palo Alto Firewall",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
            parser_version="1.0.0",
            vendor="Palo Alto Networks",
            product="PAN-OS",
        )

        assert profile.source_id == "firewall.paloalto"
        assert profile.source_name == "Palo Alto Firewall"
        assert profile.source_type == "firewall"
        assert profile.format == "syslog"
        assert profile.parser_id == "firewall_syslog_v1"
        assert profile.parser_version == "1.0.0"
        assert profile.vendor == "Palo Alto Networks"
        assert profile.product == "PAN-OS"
        assert profile.enabled is True
        assert profile.status == SourceStatus.ACTIVE.value

    def test_to_dict(self):
        profile = SourceProfile(
            source_id="firewall.test",
            source_name="Test Firewall",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
        )

        data = profile.to_dict()
        assert data["source_id"] == "firewall.test"
        assert data["source_name"] == "Test Firewall"
        assert data["source_type"] == "firewall"
        assert data["format"] == "syslog"
        assert data["parser_id"] == "firewall_syslog_v1"
        assert "created_at" in data
        assert "updated_at" in data

    def test_from_dict(self):
        data = {
            "source_id": "router.cisco",
            "source_name": "Cisco Router",
            "source_type": "router",
            "format": "json",
            "parser_id": "router_json_v1",
            "parser_version": "2.0.0",
            "vendor": "Cisco",
            "product": "IOS",
            "enabled": True,
        }

        profile = SourceProfile.from_dict(data)
        assert profile.source_id == "router.cisco"
        assert profile.source_name == "Cisco Router"
        assert profile.source_type == "router"
        assert profile.format == "json"
        assert profile.parser_id == "router_json_v1"
        assert profile.parser_version == "2.0.0"
        assert profile.vendor == "Cisco"

    def test_update_timestamp(self):
        import time
        profile = SourceProfile(
            source_id="test.source",
            source_name="Test",
            source_type="firewall",
            format="syslog",
            parser_id="test",
        )

        original = profile.updated_at
        time.sleep(0.01)
        profile.update()
        assert profile.updated_at != original


class TestSourceType:
    def test_values(self):
        values = SourceType.values()
        assert "firewall" in values
        assert "router" in values
        assert "ids" in values
        assert "unknown" in values

    def test_is_string_enum(self):
        assert SourceType.FIREWALL == "firewall"
        assert SourceType.ROUTER == "router"


class TestLogFormat:
    def test_values(self):
        values = LogFormat.values()
        assert "syslog" in values
        assert "json" in values
        assert "cef" in values
        assert "unknown" in values


class TestSourceStatus:
    def test_values(self):
        values = SourceStatus.values()
        assert "active" in values
        assert "inactive" in values
        assert "suspended" in values
