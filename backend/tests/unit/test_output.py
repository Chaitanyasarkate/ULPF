"""Unit tests for ULPF Phase 9A output formatters."""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET

import pytest

from ulpf.common.models import NormalizedEvent
from ulpf.output.base import OutputFormat
from ulpf.output.csv_formatter import CSVFormatter
from ulpf.output.cef_formatter import CEFFormatter, _escape_cef_value
from ulpf.output.json_formatter import JSONFormatter
from ulpf.output.leef_formatter import LEEFFormatter, _escape_leef_value
from ulpf.output.ocsf_formatter import OCSFFormatter
from ulpf.output.registry import OutputFormatterRegistry, UnknownFormatError, get_formatter
from ulpf.output.service import ConversionService, ConversionError
from ulpf.output.syslog_formatter import SyslogFormatter
from ulpf.output.xml_formatter import XMLFormatter


def create_test_event() -> NormalizedEvent:
    """Create a test normalized event."""
    return NormalizedEvent(
        event_id="evt-123",
        raw_event_id="raw-456",
        source_id="fw-dmz-01",
        source_type="firewall",
        format="syslog",
        parser_id="firewall_syslog_v1",
        parser_version="1.0.0",
        schema_version="1.0.0",
        event_timestamp="2026-09-07T08:01:17+00:00",
        ingestion_timestamp="2026-09-07T08:01:18+00:00",
        sha256="a" * 64,
        ocsf={
            "event": {
                "action": "accept",
                "severity": "informational",
                "time": "2026-09-07T08:01:17+00:00",
                "category": "Network Activity",
                "class_name": "Network Activity",
            },
            "source": {"ip": "10.103.83.13", "port": 12345},
            "destination": {"ip": "192.168.1.10", "port": 80},
            "network": {"protocol": "TCP"},
            "device": {"name": "fw-dmz-01", "type": "firewall"},
        },
        parsed_fields={
            "action": "accept",
            "src_ip": "10.103.83.13",
            "src_port": 12345,
            "dst_ip": "192.168.1.10",
            "dst_port": 80,
            "protocol": "TCP",
            "severity": "informational",
            "host": "fw-dmz-01",
        },
        raw_payload="<58>Sep 07 08:01:17 fw-dmz-01 %ASA-6-302013: ACCEPT inbound TCP",
    )


def create_minimal_event() -> NormalizedEvent:
    """Create a minimal test event with few fields."""
    return NormalizedEvent(
        event_id="evt-min",
        raw_event_id="raw-min",
        source_id="src-1",
        source_type="unknown",
        format="",
        parser_id="",
        parser_version="",
        schema_version="1.0.0",
        event_timestamp=None,
        ingestion_timestamp="2026-09-07T08:00:00+00:00",
        sha256="b" * 64,
        ocsf={},
        parsed_fields={},
        raw_payload="minimal raw payload",
    )


class TestJSONFormatter:
    """Tests for JSON formatter."""

    def test_format_full_event(self):
        formatter = JSONFormatter()
        event = create_test_event()
        output = formatter.format(event)

        data = json.loads(output)
        assert data["event_id"] == "evt-123"
        assert data["raw_event_id"] == "raw-456"
        assert data["source_type"] == "firewall"
        assert data["ocsf"]["event"]["action"] == "accept"
        assert data["parsed_fields"]["src_ip"] == "10.103.83.13"
        assert data["sha256"] == "a" * 64

    def test_format_minimal_event(self):
        formatter = JSONFormatter()
        event = create_minimal_event()
        output = formatter.format(event)

        data = json.loads(output)
        assert data["event_id"] == "evt-min"
        assert data["raw_event_id"] == "raw-min"
        assert data["ocsf"] == {}
        assert data["parsed_fields"] == {}

    def test_format_is_valid_json(self):
        formatter = JSONFormatter()
        event = create_test_event()
        output = formatter.format(event)

        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_format_preserves_all_fields(self):
        formatter = JSONFormatter()
        event = create_test_event()
        output = formatter.format(event)

        data = json.loads(output)
        assert data["raw_payload"] == event.raw_payload
        assert data["source_id"] == event.source_id


class TestCEFFormatter:
    """Tests for CEF formatter."""

    def test_format_full_event(self):
        formatter = CEFFormatter()
        event = create_test_event()
        output = formatter.format(event)

        assert output.startswith("CEF:0|")
        assert "ULPF" in output
        assert "src=10.103.83.13" in output
        assert "dst=192.168.1.10" in output
        assert "spt=12345" in output
        assert "dpt=80" in output
        assert "proto=TCP" in output

    def test_format_minimal_event(self):
        formatter = CEFFormatter()
        event = create_minimal_event()
        output = formatter.format(event)

        assert output.startswith("CEF:0|")
        assert "evt-min" in output

    def test_escape_equals(self):
        result = _escape_cef_value("key=value")
        assert "\\=" in result

    def test_escape_newlines(self):
        result = _escape_cef_value("line1\nline2")
        assert "\\n" in result

    def test_escape_backslash(self):
        result = _escape_cef_value("path\\to\\file")
        assert "\\\\" in result


class TestLEEFFormatter:
    """Tests for LEEF formatter."""

    def test_format_full_event(self):
        formatter = LEEFFormatter()
        event = create_test_event()
        output = formatter.format(event)

        assert output.startswith("LEEF:1.0|")
        assert "ULPF" in output
        assert "src=10.103.83.13" in output
        assert "dst=192.168.1.10" in output
        assert "srcPort=12345" in output
        assert "dstPort=80" in output
        assert "\t" in output

    def test_format_minimal_event(self):
        formatter = LEEFFormatter()
        event = create_minimal_event()
        output = formatter.format(event)

        assert output.startswith("LEEF:1.0|")
        assert "evt-min" in output

    def test_escape_pipe(self):
        result = _escape_leef_value("value|with|pipe")
        assert "\\|" in result

    def test_escape_tab(self):
        result = _escape_leef_value("val\tue")
        assert "\\t" in result


class TestXMLFormatter:
    """Tests for XML formatter."""

    def test_format_full_event(self):
        formatter = XMLFormatter()
        event = create_test_event()
        output = formatter.format(event)

        assert output.startswith('<?xml version')
        assert "<Event" in output
        assert "<Metadata>" in output
        assert "<OCSF>" in output
        assert "<ParsedFields>" in output

    def test_format_minimal_event(self):
        formatter = XMLFormatter()
        event = create_minimal_event()
        output = formatter.format(event)

        root = ET.fromstring(output)
        assert "Event" in root.tag

    def test_format_valid_xml(self):
        formatter = XMLFormatter()
        event = create_test_event()
        output = formatter.format(event)

        root = ET.fromstring(output)
        assert "Event" in root.tag

    def test_escape_special_characters(self):
        formatter = XMLFormatter()
        event = NormalizedEvent(
            event_id="evt-1",
            raw_event_id="raw-1",
            source_id="s1",
            source_type="t1",
            raw_payload='<script>alert("xss")</script>',
        )
        output = formatter.format(event)

        assert "&amp;lt;" in output


class TestCSVFormatter:
    """Tests for CSV formatter."""

    def test_format_full_event(self):
        formatter = CSVFormatter()
        event = create_test_event()
        output = formatter.format(event)

        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 2
        headers = rows[0]
        values = rows[1]

        assert "event_id" in headers
        assert "src_ip" in headers
        assert "dst_ip" in headers
        assert "10.103.83.13" in values
        assert "192.168.1.10" in values

    def test_format_minimal_event(self):
        formatter = CSVFormatter()
        event = create_minimal_event()
        output = formatter.format(event)

        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 2
        assert "evt-min" in rows[1]

    def test_csv_quoting(self):
        formatter = CSVFormatter()
        event = NormalizedEvent(
            event_id="evt-1",
            raw_event_id="raw-1",
            source_id="s1",
            source_type="t1",
            raw_payload='value,with,commas',
        )
        output = formatter.format(event)

        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        raw_idx = rows[0].index("raw_payload")
        assert rows[1][raw_idx] == "value,with,commas"

    def test_csv_escape_quotes(self):
        formatter = CSVFormatter()
        event = NormalizedEvent(
            event_id="evt-1",
            raw_event_id="raw-1",
            source_id="s1",
            source_type="t1",
            raw_payload='say "hello"',
        )
        output = formatter.format(event)

        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        raw_idx = rows[0].index("raw_payload")
        assert 'say "hello"' in rows[1][raw_idx]


class TestSyslogFormatter:
    """Tests for Syslog formatter."""

    def test_format_full_event(self):
        formatter = SyslogFormatter()
        event = create_test_event()
        output = formatter.format(event)

        assert output.startswith("<")
        assert ">" in output
        priority_match = re.match(r"<(\d+)>", output)
        assert priority_match
        priority = int(priority_match.group(1))
        assert 0 <= priority <= 191

        assert "fw-dmz-01" in output
        assert "firewall" in output
        assert "src=10.103.83.13" in output
        assert "dst=192.168.1.10" in output

    def test_format_minimal_event(self):
        formatter = SyslogFormatter()
        event = create_minimal_event()
        output = formatter.format(event)

        assert output.startswith("<")
        assert "unknown" in output

    def test_no_newlines_in_output(self):
        formatter = SyslogFormatter()
        event = create_test_event()
        output = formatter.format(event)

        assert "\n" not in output
        assert "\r" not in output


class TestOCSFFormatter:
    """Tests for OCSF formatter."""

    def test_format_full_event(self):
        formatter = OCSFFormatter()
        event = create_test_event()
        output = formatter.format(event)

        data = json.loads(output)
        assert data["event_id"] == "evt-123"
        assert data["raw_event_id"] == "raw-456"
        assert "ocsf" in data
        assert "parsed_fields" in data
        assert "provenance" in data
        assert data["provenance"]["source_type"] == "firewall"

    def test_format_minimal_event(self):
        formatter = OCSFFormatter()
        event = create_minimal_event()
        output = formatter.format(event)

        data = json.loads(output)
        assert data["event_id"] == "evt-min"
        assert data["ocsf"] == {}

    def test_preserves_raw_payload(self):
        formatter = OCSFFormatter()
        event = create_test_event()
        output = formatter.format(event)

        data = json.loads(output)
        assert data["provenance"]["raw_payload"] == event.raw_payload


class TestOutputFormatterRegistry:
    """Tests for output formatter registry."""

    def test_get_formatter_json(self):
        registry = OutputFormatterRegistry()
        registry._register_default_formatters()
        formatter = registry.get_formatter(OutputFormat.JSON)
        assert isinstance(formatter, JSONFormatter)

    def test_get_formatter_by_string(self):
        registry = OutputFormatterRegistry()
        registry._register_default_formatters()
        formatter = registry.get_formatter("cef")
        assert isinstance(formatter, CEFFormatter)

    def test_get_formatter_case_insensitive(self):
        registry = OutputFormatterRegistry()
        registry._register_default_formatters()
        formatter = registry.get_formatter("JSON")
        assert isinstance(formatter, JSONFormatter)

    def test_get_formatter_unknown_raises(self):
        registry = OutputFormatterRegistry()
        registry._register_default_formatters()
        with pytest.raises(UnknownFormatError):
            registry.get_formatter("unknown_format")

    def test_all_formatters(self):
        registry = OutputFormatterRegistry()
        registry._register_default_formatters()
        formatters = registry.all_formatters()
        assert len(formatters) == 7

    def test_list_formats(self):
        registry = OutputFormatterRegistry()
        registry._register_default_formatters()
        formats = registry.list_formats()
        assert "json" in formats
        assert "cef" in formats
        assert "leef" in formats
        assert "xml" in formats
        assert "csv" in formats
        assert "syslog" in formats
        assert "ocsf" in formats

    def test_get_formatter_convenience(self):
        formatter = get_formatter("json")
        assert isinstance(formatter, JSONFormatter)


class TestConversionService:
    """Tests for conversion service."""

    def test_convert_to_json(self):
        service = ConversionService()
        event = create_test_event()
        result = service.convert(event, "json")

        assert result.metadata.event_id == "evt-123"
        assert result.metadata.output_format == "json"
        assert result.metadata.formatter_id == "json_formatter_v1"
        assert "accept" in result.payload

    def test_convert_to_cef(self):
        service = ConversionService()
        event = create_test_event()
        result = service.convert(event, "cef")

        assert result.metadata.output_format == "cef"
        assert "CEF:0" in result.payload

    def test_convert_to_leef(self):
        service = ConversionService()
        event = create_test_event()
        result = service.convert(event, "leef")

        assert result.metadata.output_format == "leef"
        assert "LEEF:1.0" in result.payload

    def test_convert_to_xml(self):
        service = ConversionService()
        event = create_test_event()
        result = service.convert(event, "xml")

        assert result.metadata.output_format == "xml"
        assert "<?xml" in result.payload

    def test_convert_to_csv(self):
        service = ConversionService()
        event = create_test_event()
        result = service.convert(event, "csv")

        assert result.metadata.output_format == "csv"
        assert "event_id" in result.payload

    def test_convert_to_syslog(self):
        service = ConversionService()
        event = create_test_event()
        result = service.convert(event, "syslog")

        assert result.metadata.output_format == "syslog"
        assert "<" in result.payload

    def test_convert_to_ocsf(self):
        service = ConversionService()
        event = create_test_event()
        result = service.convert(event, "ocsf")

        assert result.metadata.output_format == "ocsf"
        assert "ocsf" in result.payload

    def test_convert_unknown_format_raises(self):
        service = ConversionService()
        event = create_test_event()
        with pytest.raises(UnknownFormatError):
            service.convert(event, "unknown")

    def test_convert_preserves_original_event(self):
        service = ConversionService()
        event = create_test_event()
        original_event_id = event.event_id
        result = service.convert(event, "json")

        assert event.event_id == original_event_id
        assert result.original_event_preserved is True

    def test_get_available_formats(self):
        service = ConversionService()
        formats = service.get_available_formats()
        assert len(formats) == 7
        assert any(f["output_format"] == "json" for f in formats)


class TestOutputFormatEnum:
    """Tests for OutputFormat enum."""

    def test_from_string_valid(self):
        assert OutputFormat.from_string("json") == OutputFormat.JSON
        assert OutputFormat.from_string("JSON") == OutputFormat.JSON
        assert OutputFormat.from_string("cef") == OutputFormat.CEF

    def test_from_string_invalid(self):
        with pytest.raises(ValueError):
            OutputFormat.from_string("invalid")
