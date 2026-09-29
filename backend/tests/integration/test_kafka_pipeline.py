"""Integration tests for ULPF Phase 2 Kafka streaming pipeline.

These tests require a running Kafka broker and are skipped unless
``ULPF_INTEGRATION=1`` is set in the environment.
"""

from __future__ import annotations

import os

import pytest
from kafka import KafkaProducer

from ulpf import config as config_module
from ulpf.common.hashing import sha256_str
from ulpf.common.models import EventEnvelope, ProcessingStatus, SourceType
from ulpf.kafka.consumer import UlpfConsumer
from ulpf.kafka.producer import UlpfProducer
from ulpf.kafka.topics import ensure_topics


@pytest.mark.integration
def test_kafka_producer_consumer_roundtrip():
    if not os.environ.get("ULPF_INTEGRATION"):
        pytest.skip("ULPF_INTEGRATION not set; skipping Kafka integration test")

    ensure_topics(["raw-logs"])
    producer = UlpfProducer()
    consumer = UlpfConsumer(topic="raw-logs", group_id="ulpf-test-roundtrip")

    envelope = EventEnvelope.from_raw(
        payload="src=10.0.0.1 dst=192.168.1.1 sport=1234 dport=80 proto=TCP",
        source_id="fw-01",
        source_type=SourceType.FIREWALL.value,
        fmt="syslog",
    )
    envelope.sha256 = sha256_str(envelope.raw.payload)

    published = producer.publish_raw(envelope)
    assert published is True
    producer.flush(timeout=5)

    received = []
    def handler(e):
        received.append(e)

    consumer.consume(handler, poll_timeout=5.0)

    assert len(received) == 1
    assert received[0].raw_event_id == envelope.raw_event_id
    assert received[0].raw.payload == envelope.raw.payload
    assert received[0].raw.source_id == "fw-01"
    assert received[0].raw.source_type == SourceType.FIREWALL.value
    assert received[0].sha256 == envelope.sha256
    assert received[0].processing_status == ProcessingStatus.RECEIVED.value

    producer.close()
    consumer.stop()


@pytest.mark.integration
def test_kafka_multiple_events_order():
    if not os.environ.get("ULPF_INTEGRATION"):
        pytest.skip("ULPF_INTEGRATION not set; skipping Kafka integration test")

    ensure_topics(["raw-logs"])
    producer = UlpfProducer()
    consumer = UlpfConsumer(topic="raw-logs", group_id="ulpf-test-multi")

    envelopes = []
    for i in range(5):
        env = EventEnvelope.from_raw(
            payload=f"event-{i}",
            source_id=f"s-{i}",
            source_type=SourceType.ROUTER.value,
            fmt="json",
        )
        env.sha256 = sha256_str(env.raw.payload)
        envelopes.append(env)
        assert producer.publish_raw(env) is True

    producer.flush(timeout=5)

    received = []
    def handler(e):
        received.append(e)

    consumer.consume(handler, poll_timeout=5.0)

    assert len(received) == 5
    received_ids = {e.raw_event_id for e in received}
    sent_ids = {e.raw_event_id for e in envelopes}
    assert received_ids == sent_ids

    producer.close()
    consumer.stop()


@pytest.mark.integration
def test_kafka_malformed_message_skipped():
    if not os.environ.get("ULPF_INTEGRATION"):
        pytest.skip("ULPF_INTEGRATION not set; skipping Kafka integration test")


    settings = config_module.get_settings()
    producer = KafkaProducer(
        bootstrap_servers=settings.kafka.bootstrap_servers,
        value_serializer=lambda v: v,
        key_serializer=lambda v: v.encode("utf-8") if v else None,
    )
    producer.send("raw-logs", value=b"not-valid-json")
    producer.flush(timeout=5)
    producer.close()

    consumer = UlpfConsumer(topic="raw-logs", group_id="ulpf-test-malformed")
    received = []
    def handler(e):
        received.append(e)

    consumer.consume(handler, poll_timeout=5.0)
    assert len(received) == 0
    assert consumer._error_count >= 1
    consumer.stop()
