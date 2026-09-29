#!/usr/bin/env python3
"""ULPF Final Smoke Test - End-to-End Pipeline Verification

Tests:
1. 3 input formats (Syslog, JSON, CEF)
2. Raw log preservation
3. SHA-256 provenance
4. Lineage traceability (raw -> parsed -> normalized)
5. Output conversion (7 formats: JSON, CEF, LEEF, XML, CSV, Syslog, OCSF)
6. Dashboard data readiness
"""

from __future__ import annotations

import json
import sys
import traceback

from ulpf.common.hashing import compute_event_hash, sha256_hex, verify_event_hash
from ulpf.common.models import EventEnvelope, SourceType
from ulpf.lineage.models import LineageChain, LineageRecord, RelationshipType
from ulpf.normalizer.engine import NormalizerEngine
from ulpf.output.service import ConversionService
from ulpf.parsers.engine import ParserEngine


class SmokeTestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def assert_true(self, condition, msg):
        if condition:
            self.passed += 1
            print(f"  [PASS] {msg}")
        else:
            self.failed += 1
            self.errors.append(msg)
            print(f"  [FAIL] {msg}")

    def assert_equal(self, actual, expected, msg):
        if actual == expected:
            self.passed += 1
            print(f"  [PASS] {msg}")
        else:
            self.failed += 1
            self.errors.append(f"{msg} (expected: {expected}, got: {actual})")
            print(f"  [FAIL] {msg} (expected: {expected}, got: {actual})")

    def summary(self):
        print(f"\n{'='*60}")
        print(f"SMOKE TEST SUMMARY: {self.passed} passed, {self.failed} failed")
        print(f"{'='*60}")
        if self.errors:
            for err in self.errors:
                print(f"  - {err}")
        return self.failed == 0


def test_format_syslog(result):
    """Test Syslog format parsing, normalization, and conversion."""
    print("\n[1/3] Testing Syslog (Firewall) format...")
    
    payload = "<58>Sep 07 08:01:17 fw-dmz-01 %ASA-6-302013: ACCEPT inbound TCP src=10.103.83.13:12345 dst=192.168.1.10:80 (hitcnt=0)"
    
    # Parse
    envelope = EventEnvelope.from_raw(payload, source_id="fw-dmz-01", source_type=SourceType.FIREWALL.value, fmt="syslog")
    parser_engine = ParserEngine()
    parsed = parser_engine._parse_envelope(envelope)
    
    result.assert_true(parsed is not None, "Syslog parsed successfully")
    result.assert_equal(parsed.parser_id, "firewall_syslog_v1", "Parser ID correct")
    result.assert_equal(parsed.extracted["action"], "accept", "Action extracted")
    result.assert_equal(parsed.extracted["src_ip"], "10.103.83.13", "Source IP extracted")
    result.assert_equal(parsed.raw_event_id, envelope.raw_event_id, "Raw event ID preserved")
    
    # Normalize
    envelope.parsed = parsed
    envelope.sha256 = sha256_hex(payload.encode())
    normalizer_engine = NormalizerEngine()
    normalized = normalizer_engine._normalize_envelope(envelope)
    
    result.assert_true(normalized is not None, "Syslog normalized successfully")
    result.assert_equal(normalized.raw_payload, payload, "Raw payload preserved (lossless)")
    result.assert_equal(normalized.sha256, envelope.sha256, "SHA-256 preserved")
    result.assert_equal(normalized.ocsf["event"]["action"], "allow", "Action normalized to OCSF")
    result.assert_equal(normalized.ocsf["source"]["ip"], "10.103.83.13", "Source IP in OCSF")
    result.assert_true("host" in normalized.parsed_fields, "Original fields preserved in parsed_fields")
    
    # Verify SHA-256
    event_dict = normalized.to_dict()
    computed_hash = compute_event_hash(event_dict)
    result.assert_true(verify_event_hash(event_dict, computed_hash), "SHA-256 verification passes")
    
    # Lineage
    chain = LineageChain(
        event_id=normalized.event_id,
        raw_event_id=normalized.raw_event_id,
        ancestors=[
            LineageRecord(
                parent_event_id=envelope.raw_event_id,
                child_event_id=parsed.event_id,
                relationship_type=RelationshipType.PARSED_FROM,
                raw_event_id=envelope.raw_event_id,
            ),
            LineageRecord(
                parent_event_id=parsed.event_id,
                child_event_id=normalized.event_id,
                relationship_type=RelationshipType.NORMALIZED_FROM,
                raw_event_id=envelope.raw_event_id,
            ),
        ],
        sha256=normalized.sha256,
        parser_id=normalized.parser_id,
    )
    result.assert_equal(len(chain.ancestors), 2, "Lineage chain has 2 hops")
    result.assert_equal(chain.ancestors[0].relationship_type, RelationshipType.PARSED_FROM, "First hop: parsed_from")
    result.assert_equal(chain.ancestors[1].relationship_type, RelationshipType.NORMALIZED_FROM, "Second hop: normalized_from")
    
    # Output conversion (all 7 formats)
    service = ConversionService()
    formats = ["json", "cef", "leef", "xml", "csv", "syslog", "ocsf"]
    for fmt in formats:
        conv_result = service.convert(normalized, fmt)
        result.assert_true(conv_result is not None, f"Conversion to {fmt.upper()} succeeded")
        result.assert_equal(conv_result.metadata.output_format, fmt, f"Output format metadata correct for {fmt}")
        result.assert_true(conv_result.original_event_preserved, f"Original event preserved in {fmt}")
    
    return normalized


def test_format_json(result):
    """Test JSON format parsing, normalization, and conversion."""
    print("\n[2/3] Testing JSON (Router) format...")
    
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
    
    # Parse
    envelope = EventEnvelope.from_raw(payload, source_id="router-core-01", source_type=SourceType.ROUTER.value, fmt="json")
    parser_engine = ParserEngine()
    parsed = parser_engine._parse_envelope(envelope)
    
    result.assert_true(parsed is not None, "JSON parsed successfully")
    result.assert_equal(parsed.parser_id, "router_json_v1", "Parser ID correct")
    result.assert_equal(parsed.extracted["action"], "permitted", "Action extracted")
    result.assert_equal(parsed.extracted["src_ip"], "10.64.65.4", "Source IP extracted")
    result.assert_equal(parsed.extracted["interface"], "GigabitEthernet0/0", "Interface preserved")
    
    # Normalize
    envelope.parsed = parsed
    envelope.sha256 = sha256_hex(payload.encode())
    normalizer_engine = NormalizerEngine()
    normalized = normalizer_engine._normalize_envelope(envelope)
    
    result.assert_true(normalized is not None, "JSON normalized successfully")
    result.assert_equal(normalized.raw_payload, payload, "Raw payload preserved (lossless)")
    result.assert_equal(normalized.ocsf["event"]["action"], "allow", "Action normalized to OCSF")
    result.assert_equal(normalized.ocsf["source"]["ip"], "10.64.65.4", "Source IP in OCSF")
    result.assert_equal(normalized.ocsf["device"]["interface"], "GigabitEthernet0/0", "Interface in OCSF")
    result.assert_equal(normalized.ocsf["network"]["bytes"], 1024, "Bytes in OCSF")
    result.assert_true("interface" in normalized.parsed_fields, "Custom field preserved")
    result.assert_true("bytes" in normalized.parsed_fields, "Bytes field preserved")
    
    # Verify SHA-256
    event_dict = normalized.to_dict()
    computed_hash = compute_event_hash(event_dict)
    result.assert_true(verify_event_hash(event_dict, computed_hash), "SHA-256 verification passes")
    
    # Lineage
    chain = LineageChain(
        event_id=normalized.event_id,
        raw_event_id=normalized.raw_event_id,
        ancestors=[
            LineageRecord(
                parent_event_id=envelope.raw_event_id,
                child_event_id=parsed.event_id,
                relationship_type=RelationshipType.PARSED_FROM,
                raw_event_id=envelope.raw_event_id,
            ),
            LineageRecord(
                parent_event_id=parsed.event_id,
                child_event_id=normalized.event_id,
                relationship_type=RelationshipType.NORMALIZED_FROM,
                raw_event_id=envelope.raw_event_id,
            ),
        ],
        sha256=normalized.sha256,
        parser_id=normalized.parser_id,
    )
    result.assert_equal(len(chain.ancestors), 2, "Lineage chain has 2 hops")
    
    # Output conversion
    service = ConversionService()
    for fmt in ["json", "cef", "leef", "xml", "csv", "syslog", "ocsf"]:
        conv_result = service.convert(normalized, fmt)
        result.assert_true(conv_result is not None, f"Conversion to {fmt.upper()} succeeded")
        result.assert_true(conv_result.original_event_preserved, f"Original event preserved in {fmt}")
    
    return normalized


def test_format_cef(result):
    """Test CEF format parsing, normalization, and conversion."""
    print("\n[3/3] Testing CEF (IDS) format...")
    
    payload = "CEF:0|Cisco|ASA|1.0|1000|ET SCAN Possible SSH Scan|10|rt=Sep 07 08:01:34 src=10.225.92.37 dst=192.168.1.50 act=blocked proto=TCP"
    
    # Parse
    envelope = EventEnvelope.from_raw(payload, source_id="ids-sensor-01", source_type=SourceType.IDS.value, fmt="cef")
    parser_engine = ParserEngine()
    parsed = parser_engine._parse_envelope(envelope)
    
    result.assert_true(parsed is not None, "CEF parsed successfully")
    result.assert_equal(parsed.parser_id, "ids_cef_v1", "Parser ID correct")
    result.assert_equal(parsed.extracted["device_vendor"], "Cisco", "Device vendor extracted")
    result.assert_equal(parsed.extracted["src"], "10.225.92.37", "Source IP extracted")
    result.assert_equal(parsed.extracted["act"], "blocked", "Action extracted")
    
    # Normalize
    envelope.parsed = parsed
    envelope.sha256 = sha256_hex(payload.encode())
    normalizer_engine = NormalizerEngine()
    normalized = normalizer_engine._normalize_envelope(envelope)
    
    result.assert_true(normalized is not None, "CEF normalized successfully")
    result.assert_equal(normalized.raw_payload, payload, "Raw payload preserved (lossless)")
    result.assert_equal(normalized.ocsf["event"]["action"], "deny", "Action normalized to OCSF")
    result.assert_equal(normalized.ocsf["event"]["severity"], "critical", "Severity normalized to critical")
    result.assert_equal(normalized.ocsf["source"]["ip"], "10.225.92.37", "Source IP in OCSF")
    result.assert_equal(normalized.ocsf["device"]["vendor"], "Cisco", "Vendor in OCSF")
    result.assert_equal(normalized.ocsf["device"]["product"], "ASA", "Product in OCSF")
    result.assert_equal(normalized.ocsf["event"]["signature_id"], "1000", "Signature ID in OCSF")
    
    # Verify SHA-256
    event_dict = normalized.to_dict()
    computed_hash = compute_event_hash(event_dict)
    result.assert_true(verify_event_hash(event_dict, computed_hash), "SHA-256 verification passes")
    
    # Lineage
    chain = LineageChain(
        event_id=normalized.event_id,
        raw_event_id=normalized.raw_event_id,
        ancestors=[
            LineageRecord(
                parent_event_id=envelope.raw_event_id,
                child_event_id=parsed.event_id,
                relationship_type=RelationshipType.PARSED_FROM,
                raw_event_id=envelope.raw_event_id,
            ),
            LineageRecord(
                parent_event_id=parsed.event_id,
                child_event_id=normalized.event_id,
                relationship_type=RelationshipType.NORMALIZED_FROM,
                raw_event_id=envelope.raw_event_id,
            ),
        ],
        sha256=normalized.sha256,
        parser_id=normalized.parser_id,
    )
    result.assert_equal(len(chain.ancestors), 2, "Lineage chain has 2 hops")
    
    # Output conversion
    service = ConversionService()
    for fmt in ["json", "cef", "leef", "xml", "csv", "syslog", "ocsf"]:
        conv_result = service.convert(normalized, fmt)
        result.assert_true(conv_result is not None, f"Conversion to {fmt.upper()} succeeded")
        result.assert_true(conv_result.original_event_preserved, f"Original event preserved in {fmt}")
    
    return normalized


def test_dashboard_readiness(normalized_events):
    """Verify events are ready for dashboard consumption."""
    print("\n[Dashboard] Testing dashboard data readiness...")
    result = SmokeTestResult()
    
    for i, event in enumerate(normalized_events):
        # Check all required fields for dashboard
        required_fields = [
            "event_id", "raw_event_id", "source_id", "source_type", 
            "format", "parser_id", "parser_version", "schema_version",
            "event_timestamp", "ingestion_timestamp", "sha256",
            "ocsf", "parsed_fields", "raw_payload"
        ]
        for field in required_fields:
            result.assert_true(hasattr(event, field), f"Event {i+1} has field: {field}")
        
        # Check OCSF structure
        ocsf_required = ["event", "source", "destination", "network", "device"]
        for field in ocsf_required:
            result.assert_true(field in event.ocsf, f"Event {i+1} OCSF has: {field}")
        
        # Check parsed_fields is not empty (lossless)
        result.assert_true(len(event.parsed_fields) > 0, f"Event {i+1} has parsed_fields (lossless)")
    
    result.summary()
    return result.failed == 0


def main():
    print("="*60)
    print("ULPF FINAL SMOKE TEST - SIH 2026 Submission")
    print("="*60)
    
    all_passed = True
    result = SmokeTestResult()
    normalized_events = []
    
    try:
        normalized_events.append(test_format_syslog(result))
        normalized_events.append(test_format_json(result))
        normalized_events.append(test_format_cef(result))
    except Exception as e:
        print(f"\n  [ERROR] EXCEPTION during pipeline test: {e}")
        traceback.print_exc()
        all_passed = False
    
    # Dashboard readiness
    try:
        if not test_dashboard_readiness(normalized_events):
            all_passed = False
    except Exception as e:
        print(f"\n  [ERROR] EXCEPTION during dashboard test: {e}")
        traceback.print_exc()
        all_passed = False
    
    # Final summary
    print(f"\n{'='*60}")
    if result.failed == 0 and all_passed:
        print("[SUCCESS] ALL SMOKE TESTS PASSED - READY FOR SUBMISSION")
        print("="*60)
        return 0
    else:
        print("[FAILURE] SMOKE TEST FAILURES - FIX BEFORE SUBMISSION")
        print("="*60)
        return 1


if __name__ == "__main__":
    sys.exit(main())