"""Unit tests for the core event data model."""

from __future__ import annotations

import json

import pytest

from ulpf.common.models import (
    EventEnvelope,
    EventError,
    NormalizedEvent,
    ParsedEvent,
    ProcessingStatus,
    generate_event_id,
    parse_uuid,
)


def test_raw_event_has_stable_id():
    env = EventEnvelope.from_raw("hello", source_id="fw-1", fmt="json")
    assert env.raw.raw_event_id
    assert env.raw.original_payload_bytes == len(b"hello")


def test_envelope_from_raw_sets_received_status():
    env = EventEnvelope.from_raw("Jul 15 2026 firewall %ASA-6: test", source_id="fw-1", source_type="firewall", fmt="syslog")
    assert env.raw.payload == "Jul 15 2026 firewall %ASA-6: test"
    assert env.processing_status == ProcessingStatus.RECEIVED.value
    assert env.raw_event_id == env.raw.raw_event_id


def test_envelope_roundtrip_kafka_value_preserves_payload(sample_envelope_dict):
    env = EventEnvelope.from_kafka_value(json.dumps(sample_envelope_dict).encode("utf-8"))
    assert env.raw_event_id == sample_envelope_dict["raw"]["raw_event_id"]
    assert env.processing_status == "received"
    out = env.to_dict()
    env2 = EventEnvelope.from_kafka_value(json.dumps(out).encode("utf-8"))
    assert env2.raw.payload == env.raw.payload
    assert env2.event_id == ""


def test_event_id_is_unique():
    ids = {generate_event_id() for _ in range(1000)}
    assert len(ids) == 1000


def test_parse_uuid_valid():
    uid = generate_event_id()
    parsed = parse_uuid(uid)
    assert str(parsed) == uid


def test_parse_uuid_invalid_raises():
    with pytest.raises(ValueError):
        parse_uuid("not-a-uuid")


def test_event_error_from_exception_contains_traceback():
    try:
        raise ValueError("boom")
    except ValueError as exc:
        err = EventError.from_exception("parser", "E_PARSE_001", exc)
        assert err.message == "boom"
        assert err.code == "E_PARSE_001"
        assert "ValueError" in err.traceback


def test_normalized_event_preserves_parsed_fields():
    parsed = ParsedEvent(extracted={"src_ip": "1.2.3.4", "weird_vendor_field": "x"})
    norm = NormalizedEvent(
        event_id=parsed.event_id,
        raw_event_id="raw-1",
        source_type="firewall",
        schema_version="1.0.0",
        ocsf={"src_endpoint.ip": "1.2.3.4"},
        parsed_fields=parsed.extracted,
        raw_payload="original raw",
    )
    as_dict = norm.to_dict()
    # Information preservation: the unknown field is still present.
    assert as_dict["parsed_fields"]["weird_vendor_field"] == "x"
    assert as_dict["ocsf"]["src_endpoint.ip"] == "1.2.3.4"
    assert as_dict["schema_version"] == "1.0.0"
