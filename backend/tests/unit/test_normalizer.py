"""Unit tests for ULPF Phase 4 normalizer."""

from __future__ import annotations

import json

from ulpf.common.models import (
    EventEnvelope,
    NormalizedEvent,
    ParsedEvent,
    SourceType,
)
from ulpf.normalizer.engine import (
    SCHEMA_VERSION,
    FirewallNormalizer,
    IDSNormalizer,
    NormalizerEngine,
    RouterNormalizer,
)
from ulpf.normalizer.mappings import (
    normalize_action,
    normalize_severity,
    normalize_timestamp,
)
from ulpf.normalizer.validation import validate_ip, validate_port, validate_protocol


class TestActionNormalization:
    def test_allow_actions(self):
        for raw in ["ALLOW", "allow", "ACCEPT", "accept", "permitted", "Permit", "pass"]:
            assert normalize_action(raw) == "allow"

    def test_deny_actions(self):
        for raw in ["DENY", "deny", "DROP", "drop", "blocked", "BLOCKED", "reject", "denied"]:
            assert normalize_action(raw) == "deny"

    def test_detect_actions(self):
        for raw in ["detected", "DETECTED", "alerted", "ALERT", "identified"]:
            assert normalize_action(raw) == "detect"

    def test_unknown_action(self):
        assert normalize_action("unknown-action") == "unknown"
        assert normalize_action("") == "unknown"
        assert normalize_action(None) == "unknown"


class TestSeverityNormalization:
    def test_syslog_severity_range(self):
        assert normalize_severity(0) == "low"
        assert normalize_severity(3) == "medium"
        assert normalize_severity(6) == "high"
        assert normalize_severity(7) == "high"

    def test_cef_severity_range(self):
        assert normalize_severity(1) == "low"
        assert normalize_severity(5) == "medium"
        assert normalize_severity(8) == "critical"
        assert normalize_severity(10) == "critical"

    def test_string_severity(self):
        assert normalize_severity("low") == "low"
        assert normalize_severity("medium") == "medium"
        assert normalize_severity("high") == "high"
        assert normalize_severity("critical") == "critical"
        assert normalize_severity("unknown-value") == "unknown"

    def test_none_severity(self):
        assert normalize_severity(None) == "unknown"


class TestTimestampNormalization:
    def test_iso_timestamp_passthrough(self):
        ts = "2026-09-07T08:01:17+00:00"
        assert normalize_timestamp(ts) == ts

    def test_syslog_timestamp(self):
        result = normalize_timestamp("Sep 07 08:01:17")
        assert result is not None
        assert "2026-09-07T08:01:17" in result

    def test_none_timestamp(self):
        assert normalize_timestamp(None) is None
        assert normalize_timestamp("") is None


class TestValidation:
    def test_validate_ip_valid(self):
        ip, err = validate_ip("10.0.0.1")
        assert ip == "10.0.0.1"
        assert err is None

    def test_validate_ip_invalid(self):
        ip, err = validate_ip("999.999.999.999")
        assert ip is None
        assert err is not None

    def test_validate_port_valid(self):
        port, err = validate_port(80)
        assert port == 80
        assert err is None

    def test_validate_port_invalid(self):
        port, err = validate_port(99999)
        assert port is None
        assert err is not None

    def test_validate_protocol(self):
        proto, err = validate_protocol("TCP")
        assert proto == "TCP"
        assert err is None


class TestFirewallNormalizer:
    def test_normalize_firewall_syslog(self):
        payload = "<58>Sep 07 08:01:17 fw-dmz-01 %ASA-6-302013: ACCEPT inbound TCP src=10.103.83.13:12345 dst=192.168.1.10:80 (hitcnt=0)"
        envelope = EventEnvelope.from_raw(payload, source_id="fw-dmz-01", source_type=SourceType.FIREWALL.value, fmt="syslog")
        envelope.parsed = ParsedEvent(
            raw_event_id=envelope.raw_event_id,
            source_id="fw-dmz-01",
            source_type=SourceType.FIREWALL.value,
            format="syslog",
            parser_id="firewall_syslog_v1",
            parser_version="1.0.0",
            extracted={
                "action": "accept",
                "src_ip": "10.103.83.13",
                "src_port": 12345,
                "dst_ip": "192.168.1.10",
                "dst_port": 80,
                "protocol": "TCP",
                "host": "fw-dmz-01",
                "severity": 3,
            },
            event_timestamp="2026-09-07T08:01:17+00:00",
        )
        envelope.sha256 = "abc123"

        normalizer = FirewallNormalizer()
        normalized = normalizer.normalize(envelope)

        assert isinstance(normalized, NormalizedEvent)
        assert normalized.raw_event_id == envelope.raw_event_id
        assert normalized.event_id == envelope.parsed.event_id
        assert normalized.source_id == "fw-dmz-01"
        assert normalized.source_type == SourceType.FIREWALL.value
        assert normalized.format == "syslog"
        assert normalized.parser_id == "firewall_syslog_v1"
        assert normalized.parser_version == "1.0.0"
        assert normalized.schema_version == SCHEMA_VERSION
        assert normalized.raw_payload == payload
        assert normalized.sha256 == "abc123"

        # OCSF fields
        assert normalized.ocsf["source"]["ip"] == "10.103.83.13"
        assert normalized.ocsf["source"]["port"] == 12345
        assert normalized.ocsf["destination"]["ip"] == "192.168.1.10"
        assert normalized.ocsf["destination"]["port"] == 80
        assert normalized.ocsf["network"]["protocol"] == "TCP"
        assert normalized.ocsf["event"]["action"] == "allow"
        assert normalized.ocsf["device"]["name"] == "fw-dmz-01"
        assert normalized.ocsf["device"]["type"] == "firewall"

        # Lossless: unmapped fields preserved
        assert "host" in normalized.parsed_fields
        assert "facility" not in normalized.parsed_fields  # not in extracted

    def test_action_normalized_correctly(self):
        envelope = EventEnvelope.from_raw("test", source_id="fw-1", source_type=SourceType.FIREWALL.value, fmt="syslog")
        envelope.parsed = ParsedEvent(
            raw_event_id=envelope.raw_event_id,
            source_id="fw-1",
            source_type=SourceType.FIREWALL.value,
            format="syslog",
            parser_id="firewall_syslog_v1",
            parser_version="1.0.0",
            extracted={"action": "DENY", "src_ip": "10.0.0.1", "dst_ip": "192.168.1.1"},
        )
        normalizer = FirewallNormalizer()
        normalized = normalizer.normalize(envelope)
        assert normalized.ocsf["event"]["action"] == "deny"

    def test_severity_normalized_correctly(self):
        envelope = EventEnvelope.from_raw("test", source_id="fw-1", source_type=SourceType.FIREWALL.value, fmt="syslog")
        envelope.parsed = ParsedEvent(
            raw_event_id=envelope.raw_event_id,
            source_id="fw-1",
            source_type=SourceType.FIREWALL.value,
            format="syslog",
            parser_id="firewall_syslog_v1",
            parser_version="1.0.0",
            extracted={"action": "allow", "src_ip": "10.0.0.1", "dst_ip": "192.168.1.1", "severity": 7},
        )
        normalizer = FirewallNormalizer()
        normalized = normalizer.normalize(envelope)
        assert normalized.ocsf["event"]["severity"] == "high"


class TestRouterNormalizer:
    def test_normalize_router_json(self):
        payload = json.dumps({
            "timestamp": "2026-09-07T08:01:33+00:00",
            "src_ip": "10.64.65.4",
            "dst_ip": "172.16.194.163",
            "src_port": 45123,
            "dst_port": 443,
            "protocol": "TCP",
            "action": "permitted",
            "interface": "GigabitEthernet0/0",
            "bytes": 1024,
        })
        envelope = EventEnvelope.from_raw(payload, source_id="router-core-01", source_type=SourceType.ROUTER.value, fmt="json")
        envelope.parsed = ParsedEvent(
            raw_event_id=envelope.raw_event_id,
            source_id="router-core-01",
            source_type=SourceType.ROUTER.value,
            format="json",
            parser_id="router_json_v1",
            parser_version="1.0.0",
            extracted={
                "timestamp": "2026-09-07T08:01:33+00:00",
                "src_ip": "10.64.65.4",
                "dst_ip": "172.16.194.163",
                "src_port": 45123,
                "dst_port": 443,
                "protocol": "TCP",
                "action": "permitted",
                "interface": "GigabitEthernet0/0",
                "bytes": 1024,
            },
        )
        envelope.sha256 = "def456"

        normalizer = RouterNormalizer()
        normalized = normalizer.normalize(envelope)

        assert normalized.ocsf["source"]["ip"] == "10.64.65.4"
        assert normalized.ocsf["source"]["port"] == 45123
        assert normalized.ocsf["destination"]["ip"] == "172.16.194.163"
        assert normalized.ocsf["destination"]["port"] == 443
        assert normalized.ocsf["network"]["protocol"] == "TCP"
        assert normalized.ocsf["event"]["action"] == "allow"
        assert normalized.ocsf["device"]["interface"] == "GigabitEthernet0/0"
        assert normalized.ocsf["network"]["bytes"] == 1024
        assert normalized.ocsf["event"]["time"] == "2026-09-07T08:01:33+00:00"

    def test_unknown_fields_preserved(self):
        envelope = EventEnvelope.from_raw("{}", source_id="r1", source_type=SourceType.ROUTER.value, fmt="json")
        envelope.parsed = ParsedEvent(
            raw_event_id=envelope.raw_event_id,
            source_id="r1",
            source_type=SourceType.ROUTER.value,
            format="json",
            parser_id="router_json_v1",
            parser_version="1.0.0",
            extracted={"src_ip": "10.0.0.1", "custom_field": "custom_value"},
        )
        normalizer = RouterNormalizer()
        normalized = normalizer.normalize(envelope)
        assert "custom_field" in normalized.parsed_fields
        assert normalized.parsed_fields["custom_field"] == "custom_value"


class TestIDSNormalizer:
    def test_normalize_ids_cef(self):
        payload = "CEF:0|Cisco|ASA|1.0|1000|ET SCAN Possible SSH Scan|10|rt=Sep 07 08:01:34 src=10.225.92.37 dst=192.168.1.50 act=blocked proto=TCP"
        envelope = EventEnvelope.from_raw(payload, source_id="ids-sensor-01", source_type=SourceType.IDS.value, fmt="cef")
        envelope.parsed = ParsedEvent(
            raw_event_id=envelope.raw_event_id,
            source_id="ids-sensor-01",
            source_type=SourceType.IDS.value,
            format="cef",
            parser_id="ids_cef_v1",
            parser_version="1.0.0",
            extracted={
                "device_vendor": "Cisco",
                "device_product": "ASA",
                "device_version": "1.0",
                "signature_id": "1000",
                "name": "ET SCAN Possible SSH Scan",
                "severity": "10",
                "src": "10.225.92.37",
                "dst": "192.168.1.50",
                "act": "blocked",
                "proto": "TCP",
            },
        )

        normalizer = IDSNormalizer()
        normalized = normalizer.normalize(envelope)

        assert normalized.ocsf["source"]["ip"] == "10.225.92.37"
        assert normalized.ocsf["destination"]["ip"] == "192.168.1.50"
        assert normalized.ocsf["event"]["action"] == "deny"
        assert normalized.ocsf["event"]["severity"] == "critical"
        assert normalized.ocsf["network"]["protocol"] == "TCP"
        assert normalized.ocsf["device"]["vendor"] == "Cisco"
        assert normalized.ocsf["device"]["product"] == "ASA"
        assert normalized.ocsf["event"]["signature_id"] == "1000"
        assert normalized.ocsf["event"]["name"] == "ET SCAN Possible SSH Scan"


class TestNormalizerEngine:
    def test_engine_has_default_normalizers(self):
        engine = NormalizerEngine()
        normalizers = engine._normalizers
        ids = {n.normalizer_id for n in normalizers}
        assert "firewall_normalizer_v1" in ids
        assert "router_normalizer_v1" in ids
        assert "ids_normalizer_v1" in ids

    def test_normalize_envelope_selects_correct_normalizer(self):
        engine = NormalizerEngine()
        envelope = EventEnvelope.from_raw("test", source_id="fw-1", source_type=SourceType.FIREWALL.value, fmt="syslog")
        envelope.parsed = ParsedEvent(
            raw_event_id=envelope.raw_event_id,
            source_id="fw-1",
            source_type=SourceType.FIREWALL.value,
            format="syslog",
            parser_id="firewall_syslog_v1",
            parser_version="1.0.0",
            extracted={"action": "allow", "src_ip": "10.0.0.1", "dst_ip": "192.168.1.1"},
        )
        normalizer = engine._select_normalizer(envelope)
        assert isinstance(normalizer, FirewallNormalizer)

    def test_normalize_envelope_no_normalizer_returns_none(self):
        engine = NormalizerEngine()
        envelope = EventEnvelope.from_raw("test", source_id="x", source_type="custom", fmt="unknown")
        envelope.parsed = ParsedEvent(
            raw_event_id=envelope.raw_event_id,
            source_id="x",
            source_type="custom",
            format="unknown",
            parser_id="custom_v1",
            parser_version="1.0.0",
            extracted={},
        )
        result = engine._normalize_envelope(envelope)
        assert result is None

    def test_lossless_preservation(self):
        envelope = EventEnvelope.from_raw("test payload", source_id="fw-1", source_type=SourceType.FIREWALL.value, fmt="syslog")
        envelope.parsed = ParsedEvent(
            raw_event_id=envelope.raw_event_id,
            source_id="fw-1",
            source_type=SourceType.FIREWALL.value,
            format="syslog",
            parser_id="firewall_syslog_v1",
            parser_version="1.0.0",
            extracted={
                "action": "allow",
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.1.1",
                "custom_field": "preserve_me",
            },
        )
        envelope.sha256 = "sha256value"

        normalizer = FirewallNormalizer()
        normalized = normalizer.normalize(envelope)

        # Provenance preserved
        assert normalized.raw_event_id == envelope.raw_event_id
        assert normalized.event_id == envelope.parsed.event_id
        assert normalized.raw_payload == "test payload"
        assert normalized.sha256 == "sha256value"
        assert normalized.parser_id == "firewall_syslog_v1"
        assert normalized.parser_version == "1.0.0"
        assert normalized.schema_version == SCHEMA_VERSION

        # All original fields preserved in parsed_fields (lossless)
        assert "custom_field" in normalized.parsed_fields
        assert normalized.parsed_fields["custom_field"] == "preserve_me"
        assert "src_ip" in normalized.parsed_fields
        assert "dst_ip" in normalized.parsed_fields

        # Common fields also populated in ocsf
        assert normalized.ocsf["source"]["ip"] == "10.0.0.1"
        assert normalized.ocsf["destination"]["ip"] == "192.168.1.1"
        assert normalized.ocsf["event"]["action"] == "allow"
