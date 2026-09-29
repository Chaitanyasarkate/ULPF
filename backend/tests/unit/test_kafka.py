"""Unit tests for ULPF Phase 2 Kafka layer."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from ulpf.common.models import EventEnvelope, ParsedEvent, SourceType
from ulpf.config import get_settings
from ulpf.kafka.consumer import UlpfConsumer
from ulpf.kafka.producer import UlpfProducer
from ulpf.kafka.topics import ensure_topics


class TestKafkaConfig:
    def test_default_kafka_config(self, monkeypatch):
        monkeypatch.delenv("ULPF_KAFKA_ENABLED", raising=False)
        settings = get_settings()
        assert settings.kafka.bootstrap_servers == "localhost:9092"
        assert settings.kafka.topic_raw_logs == "raw-logs"
        assert settings.kafka.enabled is False

    def test_kafka_enabled_from_env(self, monkeypatch):
        monkeypatch.setenv("ULPF_KAFKA_ENABLED", "true")
        settings = get_settings()
        assert settings.kafka.enabled is True

    def test_kafka_topics_list(self):
        settings = get_settings()
        topics = settings.kafka.topics()
        assert "raw-logs" in topics
        assert "parsed-logs" in topics
        assert "failed-events" in topics


class TestEventEnvelopeKafkaRoundtrip:
    def test_roundtrip_preserves_fields(self):
        envelope = EventEnvelope.from_raw(
            payload="src=10.0.0.1 dst=192.168.1.1",
            source_id="fw-01",
            source_type=SourceType.FIREWALL.value,
            fmt="syslog",
        )
        envelope.sha256 = "abc123"
        envelope.current_hash = "def456"

        data = envelope.to_kafka_value()
        rebuilt = EventEnvelope.from_kafka_value(data)

        assert rebuilt.raw_event_id == envelope.raw_event_id
        assert rebuilt.raw.payload == envelope.raw.payload
        assert rebuilt.raw.source_id == "fw-01"
        assert rebuilt.raw.source_type == SourceType.FIREWALL.value
        assert rebuilt.sha256 == "abc123"
        assert rebuilt.current_hash == "def456"

    def test_roundtrip_preserves_event_id(self):
        envelope = EventEnvelope.from_raw("test", source_id="s1", source_type="router", fmt="json")
        envelope.parsed = ParsedEvent(
            event_id="fixed-event-id",
            raw_event_id=envelope.raw_event_id,
            source_id="s1",
            source_type="router",
            format="json",
        )
        data = envelope.to_kafka_value()
        rebuilt = EventEnvelope.from_kafka_value(data)
        assert rebuilt.event_id == "fixed-event-id"


class TestUlpfProducer:
    @patch("ulpf.kafka.producer.KafkaProducer")
    def test_publish_raw_success(self, mock_kafka_producer_cls):
        mock_producer = MagicMock()
        mock_future = MagicMock()
        mock_future.get.return_value = None
        mock_producer.send.return_value = mock_future
        mock_kafka_producer_cls.return_value = mock_producer

        producer = UlpfProducer(bootstrap_servers="localhost:9092")
        envelope = EventEnvelope.from_raw("payload", source_id="s1", source_type="firewall", fmt="syslog")
        result = producer.publish_raw(envelope)

        assert result is True
        mock_producer.send.assert_called_once()
        call_args = mock_producer.send.call_args
        assert call_args[0][0] == "raw-logs"
        assert call_args[1]["key"] == "s1"
        assert json.loads(call_args[1]["value"].decode("utf-8"))["raw"]["payload"] == "payload"

    @patch("ulpf.kafka.producer.KafkaProducer")
    def test_publish_raw_records_failure(self, mock_kafka_producer_cls):
        mock_producer = MagicMock()
        mock_future = MagicMock()
        mock_future.get.side_effect = Exception("broker down")
        mock_producer.send.return_value = mock_future
        mock_kafka_producer_cls.return_value = mock_producer

        producer = UlpfProducer(bootstrap_servers="localhost:9092")
        envelope = EventEnvelope.from_raw("payload", source_id="s1", source_type="firewall", fmt="syslog")
        result = producer.publish_raw(envelope)

        assert result is False
        assert producer.metrics()["failed_count"] == 1

    @patch("ulpf.kafka.producer.KafkaProducer")
    def test_metrics_updated(self, mock_kafka_producer_cls):
        mock_producer = MagicMock()
        mock_future = MagicMock()
        mock_future.get.return_value = None
        mock_producer.send.return_value = mock_future
        mock_kafka_producer_cls.return_value = mock_producer

        producer = UlpfProducer(bootstrap_servers="localhost:9092")
        envelope = EventEnvelope.from_raw("p1", source_id="s1", source_type="firewall", fmt="syslog")
        producer.publish_raw(envelope)

        metrics = producer.metrics()
        assert metrics["published_count"] == 1
        assert metrics["failed_count"] == 0
        assert metrics["avg_publish_latency_ms"] >= 0


class TestUlpfConsumer:
    @patch("ulpf.kafka.consumer.KafkaConsumer")
    def test_consume_deserializes_envelope(self, mock_consumer_cls):
        mock_consumer = MagicMock()
        envelope = EventEnvelope.from_raw("test payload", source_id="fw-1", source_type="firewall", fmt="syslog")
        envelope.sha256 = "abc"
        record = MagicMock()
        record.value = envelope.to_kafka_value()
        record.offset = 0
        record.topic = "raw-logs"
        record.partition = 0

        mock_tp = MagicMock()
        mock_tp.topic = "raw-logs"
        mock_tp.partition = 0
        mock_message = {mock_tp: [record]}
        mock_consumer.poll.side_effect = [mock_message, StopIteration]
        mock_consumer_cls.return_value = mock_consumer

        consumer = UlpfConsumer(bootstrap_servers="localhost:9092", topic="raw-logs", group_id="test")
        received = []
        consumer.consume(lambda e: received.append(e), poll_timeout=0.1)

        assert len(received) == 1
        assert received[0].raw_event_id == envelope.raw_event_id
        assert received[0].raw.payload == "test payload"
        assert received[0].sha256 == "abc"

    @patch("ulpf.kafka.consumer.KafkaConsumer")
    def test_consumer_skips_malformed_message(self, mock_consumer_cls):
        mock_consumer = MagicMock()
        record = MagicMock()
        record.value = b"not-valid-json"
        record.offset = 0
        record.topic = "raw-logs"
        record.partition = 0

        mock_tp = MagicMock()
        mock_tp.topic = "raw-logs"
        mock_tp.partition = 0
        mock_message = {mock_tp: [record]}
        mock_consumer.poll.side_effect = [mock_message, StopIteration]
        mock_consumer_cls.return_value = mock_consumer

        consumer = UlpfConsumer(bootstrap_servers="localhost:9092", topic="raw-logs", group_id="test")
        received = []
        consumer.consume(lambda e: received.append(e), poll_timeout=0.1)

        assert len(received) == 0
        assert consumer._error_count == 1

    @patch("ulpf.kafka.consumer.KafkaConsumer")
    def test_consumer_metrics(self, mock_consumer_cls):
        mock_consumer = MagicMock()
        record = MagicMock()
        envelope = EventEnvelope.from_raw("test", source_id="s1", source_type="firewall", fmt="syslog")
        record.value = envelope.to_kafka_value()
        record.offset = 0
        record.topic = "raw-logs"
        record.partition = 0

        mock_tp = MagicMock()
        mock_tp.topic = "raw-logs"
        mock_tp.partition = 0
        mock_message = {mock_tp: [record]}
        mock_consumer.poll.side_effect = [mock_message, StopIteration]
        mock_consumer_cls.return_value = mock_consumer

        consumer = UlpfConsumer(bootstrap_servers="localhost:9092", topic="raw-logs", group_id="test")
        consumer.consume(lambda e: None, poll_timeout=0.1)

        metrics = consumer.metrics()
        assert metrics["consumed_count"] == 1
        assert metrics["error_count"] == 0


class TestEnsureTopics:
    @patch("ulpf.kafka.topics._KAFKA_ADMIN_AVAILABLE", False)
    def test_ensure_topics_skips_when_admin_unavailable(self):
        result = ensure_topics(["raw-logs"])
        assert result == ["raw-logs"]
