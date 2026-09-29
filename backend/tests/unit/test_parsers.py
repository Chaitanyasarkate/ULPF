"""Unit tests for ULPF Phase 3 parsers."""

from __future__ import annotations

import json

import pytest

from ulpf.common.models import EventEnvelope, SourceType
from ulpf.parsers.cef import IDSCEFParser, _parse_cef_line
from ulpf.parsers.detection import detect_format, detect_source_type
from ulpf.parsers.engine import ParserEngine
from ulpf.parsers.json import RouterJsonParser
from ulpf.parsers.registry import ParserRegistry
from ulpf.parsers.syslog import FirewallSyslogParser, _parse_syslog_line


class TestSyslogParser:
    def test_parse_firewall_syslog(self):
        payload = "<58>Sep 07 08:01:17 fw-dmz-01 %ASA-6-302013: ACCEPT inbound TCP src=10.103.83.13:12345 dst=192.168.1.10:80 (hitcnt=0)"
        envelope = EventEnvelope.from_raw(payload, source_id="fw-dmz-01", source_type=SourceType.FIREWALL.value, fmt="syslog")
        parser = FirewallSyslogParser()
        parsed = parser.parse(envelope)

        assert parsed.parser_id == "firewall_syslog_v1"
        assert parsed.parser_version == "1.0.0"
        assert parsed.raw_event_id == envelope.raw_event_id
        assert parsed.source_id == "fw-dmz-01"
        assert parsed.extracted["action"] == "accept"
        assert parsed.extracted["src_ip"] == "10.103.83.13"
        assert parsed.extracted["src_port"] == 12345
        assert parsed.extracted["dst_ip"] == "192.168.1.10"
        assert parsed.extracted["dst_port"] == 80
        assert parsed.extracted["protocol"] == "TCP"

    def test_parse_syslog_icmp(self):
        payload = "<44>Sep 07 08:01:18 fw-edge-01 %ASA-6-302013: ALLOW inbound ICMP src=10.128.148.2 dst=192.168.1.1 (hitcnt=0)"
        envelope = EventEnvelope.from_raw(payload, source_id="fw-edge-01", source_type=SourceType.FIREWALL.value, fmt="syslog")
        parser = FirewallSyslogParser()
        parsed = parser.parse(envelope)

        assert parsed.extracted["action"] == "allow"
        assert parsed.extracted["src_ip"] == "10.128.148.2"
        assert parsed.extracted["protocol"] == "ICMP"
        assert parsed.extracted.get("src_port") is None
        assert parsed.extracted.get("dst_port") is None

    def test_parse_syslog_malformed_returns_dict(self):
        result = _parse_syslog_line("not-syslog-at-all")
        assert result["message"] == "not-syslog-at-all"

    def test_parse_syslog_without_priority(self):
        payload = "Sep 07 08:01:17 fw01 %ASA-6-302013: Built"
        result = _parse_syslog_line(payload)
        assert result["host"] == "fw01"
        assert result["message"] == "%ASA-6-302013: Built"


class TestJsonParser:
    def test_parse_router_json(self):
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
        parser = RouterJsonParser()
        parsed = parser.parse(envelope)

        assert parsed.parser_id == "router_json_v1"
        assert parsed.parser_version == "1.0.0"
        assert parsed.raw_event_id == envelope.raw_event_id
        assert parsed.extracted["src_ip"] == "10.64.65.4"
        assert parsed.extracted["dst_ip"] == "172.16.194.163"
        assert parsed.extracted["protocol"] == "TCP"
        assert parsed.extracted["action"] == "permitted"
        assert parsed.extracted["interface"] == "GigabitEthernet0/0"

    def test_parse_invalid_json_raises(self):
        envelope = EventEnvelope.from_raw("not-json", source_id="r1", source_type=SourceType.ROUTER.value, fmt="json")
        parser = RouterJsonParser()
        with pytest.raises(ValueError):
            parser.parse(envelope)


class TestCEFParser:
    def test_parse_ids_cef(self):
        payload = "CEF:0|Cisco|ASA|1.0|1000|ET SCAN Possible SSH Scan|10|rt=Sep 07 08:01:34 src=10.225.92.37 dst=192.168.1.50 act=blocked proto=TCP"
        envelope = EventEnvelope.from_raw(payload, source_id="ids-sensor-01", source_type=SourceType.IDS.value, fmt="cef")
        parser = IDSCEFParser()
        parsed = parser.parse(envelope)

        assert parsed.parser_id == "ids_cef_v1"
        assert parsed.parser_version == "1.0.0"
        assert parsed.raw_event_id == envelope.raw_event_id
        assert parsed.extracted["device_vendor"] == "Cisco"
        assert parsed.extracted["device_product"] == "ASA"
        assert parsed.extracted["signature_id"] == "1000"
        assert parsed.extracted["name"] == "ET SCAN Possible SSH Scan"
        assert parsed.extracted["severity"] == "10"
        assert parsed.extracted["src"] == "10.225.92.37"
        assert parsed.extracted["dst"] == "192.168.1.50"
        assert parsed.extracted["act"] == "blocked"
        assert parsed.extracted["proto"] == "TCP"

    def test_parse_cef_malformed_returns_dict(self):
        result = _parse_cef_line("not-cef-at-all")
        assert result["message"] == "not-cef-at-all"


class TestDetection:
    def test_detect_syslog(self):
        assert detect_format("<13>Jul 15 2026 10:23:41 fw01 %ASA-6: test") == "syslog"

    def test_detect_json(self):
        assert detect_format('{"key": "value"}') == "json"

    def test_detect_json_array(self):
        assert detect_format('[{"a": 1}]') == "json"

    def test_detect_cef(self):
        assert detect_format("CEF:0|Vendor|Product|1.0|1000|Signature|1|src=1.2.3.4") == "cef"

    def test_detect_explicit_format(self):
        assert detect_format("plain text", explicit_format="syslog") == "syslog"

    def test_detect_unknown(self):
        assert detect_format("plain text with no format") == "unknown"

    def test_detect_source_type_explicit(self):
        assert detect_source_type(explicit_source_type="firewall") == "firewall"

    def test_detect_source_type_unknown(self):
        assert detect_source_type() == "unknown"


class TestParserRegistry:
    def test_register_and_lookup_firewall(self):
        registry = ParserRegistry()
        registry.register(FirewallSyslogParser())
        envelope = EventEnvelope.from_raw("test", source_id="fw-1", source_type=SourceType.FIREWALL.value, fmt="syslog")
        parser = registry.lookup(envelope)
        assert isinstance(parser, FirewallSyslogParser)

    def test_register_and_lookup_router(self):
        registry = ParserRegistry()
        registry.register(RouterJsonParser())
        envelope = EventEnvelope.from_raw('{"a": 1}', source_id="r-1", source_type=SourceType.ROUTER.value, fmt="json")
        parser = registry.lookup(envelope)
        assert isinstance(parser, RouterJsonParser)

    def test_lookup_returns_none_when_no_match(self):
        registry = ParserRegistry()
        registry.register(FirewallSyslogParser())
        envelope = EventEnvelope.from_raw('{"a": 1}', source_id="r-1", source_type=SourceType.ROUTER.value, fmt="json")
        parser = registry.lookup(envelope)
        assert parser is None

    def test_registry_all_parsers(self):
        registry = ParserRegistry()
        registry.register(FirewallSyslogParser())
        registry.register(RouterJsonParser())
        assert len(registry.all_parsers()) == 2


class TestParserEngine:
    def test_engine_has_default_parsers(self):
        engine = ParserEngine()
        parsers = engine.registry.all_parsers()
        assert len(parsers) == 3
        ids = {p.parser_id for p in parsers}
        assert "firewall_syslog_v1" in ids
        assert "router_json_v1" in ids
        assert "ids_cef_v1" in ids

    def test_parse_envelope_selects_correct_parser(self):
        engine = ParserEngine()
        envelope = EventEnvelope.from_raw(
            "<58>Sep 07 08:01:17 fw-dmz-01 %ASA-6-302013: ACCEPT inbound TCP src=10.0.0.1 dst=192.168.1.1",
            source_id="fw-dmz-01",
            source_type=SourceType.FIREWALL.value,
            fmt="syslog",
        )
        parsed = engine._parse_envelope(envelope)
        assert parsed is not None
        assert parsed.parser_id == "firewall_syslog_v1"
        assert parsed.extracted["action"] == "accept"

    def test_parse_envelope_no_parser_returns_none(self):
        engine = ParserEngine()
        envelope = EventEnvelope.from_raw("unknown format", source_id="x", source_type="custom", fmt="unknown")
        parsed = engine._parse_envelope(envelope)
        assert parsed is None

    def test_handle_envelope_failure_publishes_failed(self):
        engine = ParserEngine()
        envelope = EventEnvelope.from_raw("not-json", source_id="r1", source_type=SourceType.ROUTER.value, fmt="json")

        published_failed = []

        def mock_publish_failed(env, error):
            published_failed.append((env, error))

        engine._publish_failed = mock_publish_failed
        engine._handle_envelope(envelope)

        assert len(published_failed) == 1
        assert published_failed[0][1].code == "E_PARSE_001"
