"""Integration tests for ULPF Phase 3 parser engine.

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
from ulpf.parsers.engine import ParserEngine


@pytest.mark.integration
def test_parser_engine_firewall_syslog_end_to_end():
    if not os.environ.get("ULPF_INTEGRATION"):
        pytest.skip("ULPF_INTEGRATION not set; skipping parser integration test")

    ensure_topics(["raw-logs", "parsed-logs", "failed-events"])
    producer = UlpfProducer()
    engine = ParserEngine()

    payload = "<58>Sep 07 08:01:17 fw-dmz-01 %ASA-6-302013: ACCEPT inbound TCP src=10.103.83.13:12345 dst=192.168.1.10:80 (hitcnt=0)"
    envelope = EventEnvelope.from_raw(payload, source_id="fw-dmz-01", source_type=SourceType.FIREWALL.value, fmt="syslog")

    assert producer.publish_raw(envelope) is True
    producer.flush(timeout=5)
    producer.close()

    engine.start()
    time.sleep(3)
    engine.stop()

    consumer = UlpfConsumer(topic="parsed-logs", group_id="ulpf-test-parser-fw")
    received = []
    def handler(e):
        received.append(e)

    consumer.consume(handler, poll_timeout=5.0)

    assert len(received) == 1
    parsed = received[0].parsed
    assert parsed is not None
    assert parsed.parser_id == "firewall_syslog_v1"
    assert parsed.parser_version == "1.0.0"
    assert parsed.raw_event_id == envelope.raw_event_id
    assert parsed.extracted["action"] == "accept"
    assert parsed.extracted["src_ip"] == "10.103.83.13"
    assert parsed.extracted["src_port"] == 12345
    assert received[0].processing_status == ProcessingStatus.PARSED.value
    consumer.stop()


@pytest.mark.integration
def test_parser_engine_router_json_end_to_end():
    if not os.environ.get("ULPF_INTEGRATION"):
        pytest.skip("ULPF_INTEGRATION not set; skipping parser integration test")

    ensure_topics(["raw-logs", "parsed-logs", "failed-events"])
    producer = UlpfProducer()
    engine = ParserEngine()

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

    assert producer.publish_raw(envelope) is True
    producer.flush(timeout=5)
    producer.close()

    engine.start()
    time.sleep(3)
    engine.stop()

    consumer = UlpfConsumer(topic="parsed-logs", group_id="ulpf-test-parser-rtr")
    received = []
    def handler(e):
        received.append(e)

    consumer.consume(handler, poll_timeout=5.0)

    assert len(received) == 1
    parsed = received[0].parsed
    assert parsed is not None
    assert parsed.parser_id == "router_json_v1"
    assert parsed.parser_version == "1.0.0"
    assert parsed.extracted["src_ip"] == "10.64.65.4"
    assert parsed.extracted["action"] == "permitted"
    consumer.stop()


@pytest.mark.integration
def test_parser_engine_ids_cef_end_to_end():
    if not os.environ.get("ULPF_INTEGRATION"):
        pytest.skip("ULPF_INTEGRATION not set; skipping parser integration test")

    ensure_topics(["raw-logs", "parsed-logs", "failed-events"])
    producer = UlpfProducer()
    engine = ParserEngine()

    payload = "CEF:0|Cisco|ASA|1.0|1000|ET SCAN Possible SSH Scan|10|rt=Sep 07 08:01:34 src=10.225.92.37 dst=192.168.1.50 act=blocked proto=TCP"
    envelope = EventEnvelope.from_raw(payload, source_id="ids-sensor-01", source_type=SourceType.IDS.value, fmt="cef")

    assert producer.publish_raw(envelope) is True
    producer.flush(timeout=5)
    producer.close()

    engine.start()
    time.sleep(3)
    engine.stop()

    consumer = UlpfConsumer(topic="parsed-logs", group_id="ulpf-test-parser-ids")
    received = []
    def handler(e):
        received.append(e)

    consumer.consume(handler, poll_timeout=5.0)

    assert len(received) == 1
    parsed = received[0].parsed
    assert parsed is not None
    assert parsed.parser_id == "ids_cef_v1"
    assert parsed.parser_version == "1.0.0"
    assert parsed.extracted["device_vendor"] == "Cisco"
    assert parsed.extracted["src"] == "10.225.92.37"
    assert parsed.extracted["act"] == "blocked"
    consumer.stop()
