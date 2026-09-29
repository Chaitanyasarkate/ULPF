"""Integration tests for ULPF Phase 4 normalizer engine.

These tests require a running Kafka broker and are skipped unless
``ULPF_INTEGRATION=1`` is set in the environment.
"""

from __future__ import annotations

import json
import os
import time

import pytest

from ulpf.common.models import EventEnvelope, ProcessingStatus, SourceType
from ulpf.kafka.consumer import UlpfConsumer
from ulpf.kafka.producer import UlpfProducer
from ulpf.kafka.topics import ensure_topics
from ulpf.normalizer.engine import NormalizerEngine


@pytest.mark.integration
def test_normalizer_engine_firewall_end_to_end():
    if not os.environ.get("ULPF_INTEGRATION"):
        pytest.skip("ULPF_INTEGRATION not set; skipping normalizer integration test")

    ensure_topics(["parsed-logs", "normalized-events", "failed-events"])
    producer = UlpfProducer()
    normalizer = NormalizerEngine()

    payload = "<58>Sep 07 08:01:17 fw-dmz-01 %ASA-6-302013: ACCEPT inbound TCP src=10.103.83.13:12345 dst=192.168.1.10:80 (hitcnt=0)"
    envelope = EventEnvelope.from_raw(payload, source_id="fw-dmz-01", source_type=SourceType.FIREWALL.value, fmt="syslog")
    envelope.parsed = __import__("ulpf.common.models", fromlist=["ParsedEvent"]).ParsedEvent(
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

    assert producer.publish_parsed(envelope, key=envelope.parsed.event_id) is True
    producer.flush(timeout=5)
    producer.close()

    normalizer.start()
    time.sleep(3)
    normalizer.stop()

    consumer = UlpfConsumer(topic="normalized-events", group_id="ulpf-test-norm-fw")
    received = []
    def handler(e):
        received.append(e)

    consumer.consume(handler, poll_timeout=5.0)

    assert len(received) == 1
    normalized = received[0].normalized
    assert normalized is not None
    assert normalized.parser_id == "firewall_syslog_v1"
    assert normalized.ocsf["source"]["ip"] == "10.103.83.13"
    assert normalized.ocsf["destination"]["ip"] == "192.168.1.10"
    assert normalized.ocsf["event"]["action"] == "allow"
    assert received[0].processing_status == ProcessingStatus.NORMALIZED.value
    consumer.stop()


@pytest.mark.integration
def test_normalizer_engine_router_end_to_end():
    if not os.environ.get("ULPF_INTEGRATION"):
        pytest.skip("ULPF_INTEGRATION not set; skipping normalizer integration test")

    ensure_topics(["parsed-logs", "normalized-events", "failed-events"])
    producer = UlpfProducer()
    normalizer = NormalizerEngine()

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
    envelope.parsed = __import__("ulpf.common.models", fromlist=["ParsedEvent"]).ParsedEvent(
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

    assert producer.publish_parsed(envelope, key=envelope.parsed.event_id) is True
    producer.flush(timeout=5)
    producer.close()

    normalizer.start()
    time.sleep(3)
    normalizer.stop()

    consumer = UlpfConsumer(topic="normalized-events", group_id="ulpf-test-norm-rtr")
    received = []
    def handler(e):
        received.append(e)

    consumer.consume(handler, poll_timeout=5.0)

    assert len(received) == 1
    normalized = received[0].normalized
    assert normalized is not None
    assert normalized.parser_id == "router_json_v1"
    assert normalized.ocsf["source"]["ip"] == "10.64.65.4"
    assert normalized.ocsf["event"]["action"] == "allow"
    consumer.stop()


@pytest.mark.integration
def test_normalizer_engine_ids_end_to_end():
    if not os.environ.get("ULPF_INTEGRATION"):
        pytest.skip("ULPF_INTEGRATION not set; skipping normalizer integration test")

    ensure_topics(["parsed-logs", "normalized-events", "failed-events"])
    producer = UlpfProducer()
    normalizer = NormalizerEngine()

    payload = "CEF:0|Cisco|ASA|1.0|1000|ET SCAN Possible SSH Scan|10|rt=Sep 07 08:01:34 src=10.225.92.37 dst=192.168.1.50 act=blocked proto=TCP"
    envelope = EventEnvelope.from_raw(payload, source_id="ids-sensor-01", source_type=SourceType.IDS.value, fmt="cef")
    envelope.parsed = __import__("ulpf.common.models", fromlist=["ParsedEvent"]).ParsedEvent(
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

    assert producer.publish_parsed(envelope, key=envelope.parsed.event_id) is True
    producer.flush(timeout=5)
    producer.close()

    normalizer.start()
    time.sleep(3)
    normalizer.stop()

    consumer = UlpfConsumer(topic="normalized-events", group_id="ulpf-test-norm-ids")
    received = []
    def handler(e):
        received.append(e)

    consumer.consume(handler, poll_timeout=5.0)

    assert len(received) == 1
    normalized = received[0].normalized
    assert normalized is not None
    assert normalized.parser_id == "ids_cef_v1"
    assert normalized.ocsf["source"]["ip"] == "10.225.92.37"
    assert normalized.ocsf["destination"]["ip"] == "192.168.1.50"
    assert normalized.ocsf["event"]["action"] == "deny"
    assert normalized.ocsf["event"]["severity"] == "critical"
    consumer.stop()
