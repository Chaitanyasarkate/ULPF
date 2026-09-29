"""Integration tests for the Phase 0 foundation stack.

These tests exercise multiple foundation modules together (config + models +
hashing) in a single, hermetic flow — no external services required. True
service-level integration tests (Kafka/MinIO/OpenSearch/PostgreSQL) will be
added in their respective phases and marked accordingly.
"""

from __future__ import annotations

from ulpf import config as config_module
from ulpf.common.hashing import compute_event_hash, verify_event_hash
from ulpf.common.models import (
    SCHEMA_VERSION,
    EventEnvelope,
    NormalizedEvent,
    ParsedEvent,
    ProcessingStatus,
)


def test_full_foundation_roundtrip_pipeline():
    """Simulate one event moving through the foundation: raw -> parsed ->
    normalized, then fingerprinted, serialized, deserialized, and verified."""
    settings = config_module.get_settings()
    seed = settings.security.lineage_hash_seed

    # 1. Raw receipt
    envelope = EventEnvelope.from_raw(
        payload="Jul 15 2026 10:23:41 firewall1 %ASA-6-302013: Built inbound TCP",
        source_id="firewall-01",
        source_type="firewall",
        fmt="syslog",
    )
    assert envelope.processing_status == ProcessingStatus.RECEIVED.value

    # 2. Parsing produces a parsed event
    parsed = ParsedEvent(
        raw_event_id=envelope.raw_event_id,
        source_id=envelope.raw.source_id,
        source_type=envelope.raw.source_type,
        format="syslog",
        parser_id="Firewall-Syslog-v1",
        parser_version="1.0.0",
        extracted={"src_ip": "192.168.1.5", "action": "Built"},
        event_timestamp="2026-07-15T10:23:41Z",
    )
    envelope.parsed = parsed
    envelope.parser_id = parsed.parser_id
    envelope.parser_version = parsed.parser_version

    # 3. Normalization (OCSF-style, preserving parsed fields)
    normalized = NormalizedEvent(
        event_id=parsed.event_id,
        raw_event_id=parsed.raw_event_id,
        source_id=parsed.source_id,
        source_type=parsed.source_type,
        format=parsed.format,
        parser_id=parsed.parser_id,
        parser_version=parsed.parser_version,
        schema_version=SCHEMA_VERSION,
        event_timestamp=parsed.event_timestamp,
        ocsf={"src_endpoint.ip": "192.168.1.5", "action": "Built"},
        parsed_fields=parsed.extracted,
        raw_payload=envelope.raw.payload,
    )
    envelope.normalized = normalized

    # 4. Fingerprint normalized content for tamper-evidence
    norm_dict = normalized.to_dict()
    fingerprint = compute_event_hash(norm_dict, seed=seed)
    envelope.sha256 = fingerprint
    assert verify_event_hash(norm_dict, fingerprint, seed=seed)

    # 5. Serialize the whole envelope (as Kafka would) and deserialize
    data = envelope.to_kafka_value()
    rebuilt = EventEnvelope.from_kafka_value(data)

    assert rebuilt.event_id == parsed.event_id
    assert rebuilt.raw_event_id == envelope.raw_event_id
    assert rebuilt.normalized is not None
    assert rebuilt.normalized.ocsf["src_endpoint.ip"] == "192.168.1.5"
    # Lossless: parsed_fields preserved end-to-end
    assert rebuilt.normalized.parsed_fields["src_ip"] == "192.168.1.5"

    # 6. Tamper evidence: altering the normalized event's stored raw payload
    #    invalidates the fingerprint (proves lossless retention was modified).
    rebuilt.normalized.raw_payload += " TAMPERED"
    assert not verify_event_hash(rebuilt.normalized.to_dict(), fingerprint, seed=seed)
