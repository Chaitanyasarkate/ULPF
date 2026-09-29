"""Kafka producer service for ULPF."""

from __future__ import annotations

import logging
import time
from typing import Any

from ulpf.common.models import EventEnvelope
from ulpf.config import get_settings

logger = logging.getLogger("ulpf.kafka.producer")

try:
    from kafka import KafkaProducer
    from kafka.errors import KafkaError

    _KAFKA_PRODUCER_AVAILABLE = True
except Exception:  # noqa: BLE001  # pragma: no cover - optional dependency guard
    _KAFKA_PRODUCER_AVAILABLE = False


class UlpfProducer:
    """Reusable Kafka producer for ULPF event envelopes.

    Serializes ``EventEnvelope`` instances using the existing
    ``EventEnvelope.to_kafka_value()`` method and publishes them to the
    configured ``raw-logs`` topic.
    """

    def __init__(
        self,
        bootstrap_servers: str | None = None,
        topic_raw_logs: str | None = None,
        topic_parsed_logs: str | None = None,
        topic_normalized: str | None = None,
        topic_failed: str | None = None,
        topic_schema_drift: str | None = None,
    ) -> None:
        settings = get_settings()
        self.bootstrap_servers = bootstrap_servers or settings.kafka.bootstrap_servers
        self.topic_raw_logs = topic_raw_logs or settings.kafka.topic_raw_logs
        self.topic_parsed_logs = topic_parsed_logs or settings.kafka.topic_parsed_logs
        self.topic_normalized = topic_normalized or settings.kafka.topic_normalized
        self.topic_failed = topic_failed or settings.kafka.topic_failed
        self.topic_schema_drift = topic_schema_drift or settings.kafka.topic_schema_drift

        self._producer: Any = None
        self._publish_latencies: list[float] = []
        self._failed_count: int = 0

    @property
    def producer(self) -> Any:
        if self._producer is None:
            if not _KAFKA_PRODUCER_AVAILABLE:
                raise RuntimeError("kafka-python is not installed")
            self._producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: v,
                key_serializer=lambda v: v.encode("utf-8") if v else None,
                acks="all",
                retries=5,
                retry_backoff_ms=500,
                request_timeout_ms=30000,
                max_block_ms=120000,
            )
            logger.info("Kafka producer connected to %s", self.bootstrap_servers)
        return self._producer

    def _record_latency(self, start: float) -> None:
        latency = time.monotonic() - start
        self._publish_latencies.append(latency)
        if len(self._publish_latencies) > 1000:
            self._publish_latencies.pop(0)

    def publish_raw(self, envelope: EventEnvelope, key: str | None = None) -> bool:
        """Publish a raw event envelope to the ``raw-logs`` topic.

        Args:
            envelope: The event envelope to publish.
            key: Optional message key. Defaults to ``source_id``.

        Returns:
            True if the message was successfully accepted by the broker.
        """
        start = time.monotonic()
        try:
            key = key or envelope.raw.source_id
            future = self.producer.send(
                self.topic_raw_logs,
                value=envelope.to_kafka_value(),
                key=key,
            )
            future.get(timeout=10)
            self._record_latency(start)
            logger.debug(
                "Published raw event raw_event_id=%s to topic=%s",
                envelope.raw_event_id,
                self.topic_raw_logs,
            )
            return True
        except KafkaError as exc:
            self._failed_count += 1
            logger.error("Failed to publish raw event %s: %s", envelope.raw_event_id, exc)
            return False
        except Exception as exc:  # noqa: BLE001
            self._failed_count += 1
            logger.error("Unexpected error publishing raw event %s: %s", envelope.raw_event_id, exc)
            return False

    def publish_raw_async(self, envelope: EventEnvelope, key: str | None = None) -> Any:
        """Publish a raw event envelope asynchronously.

        Returns the ``Future`` from the underlying producer so the caller
        can attach callbacks or wait for completion.
        """
        key = key or envelope.raw.source_id
        future = self.producer.send(
            self.topic_raw_logs,
            value=envelope.to_kafka_value(),
            key=key,
        )
        logger.debug("Queued raw event raw_event_id=%s for async publish", envelope.raw_event_id)
        return future

    def flush(self, timeout: float = 10.0) -> None:
        """Block until all pending messages are published or timeout expires."""
        if self._producer is not None:
            self._producer.flush(timeout=timeout)

    def close(self) -> None:
        """Close the producer and release all resources."""
        if self._producer is not None:
            try:
                self._producer.flush(timeout=5)
                self._producer.close(timeout=5)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Error closing Kafka producer: %s", exc)
            finally:
                self._producer = None
        logger.info("Kafka producer closed")

    def publish_normalized(self, envelope: EventEnvelope, key: str | None = None) -> bool:
        """Publish a normalized event envelope to the ``normalized-events`` topic.

        Args:
            envelope: The normalized event envelope to publish.
            key: Optional message key. Defaults to ``event_id``.

        Returns:
            True if the message was successfully accepted by the broker.
        """
        start = time.monotonic()
        try:
            key = key or (envelope.normalized.event_id if envelope.normalized else envelope.raw_event_id)
            future = self.producer.send(
                self.topic_normalized,
                value=envelope.to_kafka_value(),
                key=key,
            )
            future.get(timeout=10)
            self._record_latency(start)
            logger.debug(
                "Published normalized event raw_event_id=%s to topic=%s",
                envelope.raw_event_id,
                self.topic_normalized,
            )
            return True
        except KafkaError as exc:
            self._failed_count += 1
            logger.error("Failed to publish normalized event %s: %s", envelope.raw_event_id, exc)
            return False
        except Exception as exc:  # noqa: BLE001
            self._failed_count += 1
            logger.error("Unexpected error publishing normalized event %s: %s", envelope.raw_event_id, exc)
            return False

    def publish_failed(self, envelope: EventEnvelope, key: str | None = None) -> bool:
        """Publish a failed event envelope to the ``failed-events`` topic.

        Args:
            envelope: The failed event envelope to publish.
            key: Optional message key. Defaults to ``raw_event_id``.

        Returns:
            True if the message was successfully accepted by the broker.
        """
        start = time.monotonic()
        try:
            key = key or envelope.raw_event_id
            future = self.producer.send(
                self.topic_failed,
                value=envelope.to_kafka_value(),
                key=key,
            )
            future.get(timeout=10)
            self._record_latency(start)
            logger.debug(
                "Published failed event raw_event_id=%s to topic=%s",
                envelope.raw_event_id,
                self.topic_failed,
            )
            return True
        except KafkaError as exc:
            self._failed_count += 1
            logger.error("Failed to publish failed event %s: %s", envelope.raw_event_id, exc)
            return False
        except Exception as exc:  # noqa: BLE001
            self._failed_count += 1
            logger.error("Unexpected error publishing failed event %s: %s", envelope.raw_event_id, exc)
            return False

    def publish_parsed(self, envelope: EventEnvelope, key: str | None = None) -> bool:
        """Publish a parsed event envelope to the ``parsed-logs`` topic.

        Args:
            envelope: The parsed event envelope to publish.
            key: Optional message key. Defaults to ``event_id``.

        Returns:
            True if the message was successfully accepted by the broker.
        """
        start = time.monotonic()
        try:
            key = key or (envelope.parsed.event_id if envelope.parsed else envelope.raw_event_id)
            future = self.producer.send(
                self.topic_parsed_logs,
                value=envelope.to_kafka_value(),
                key=key,
            )
            future.get(timeout=10)
            self._record_latency(start)
            logger.debug(
                "Published parsed event raw_event_id=%s to topic=%s",
                envelope.raw_event_id,
                self.topic_parsed_logs,
            )
            return True
        except KafkaError as exc:
            self._failed_count += 1
            logger.error("Failed to publish parsed event %s: %s", envelope.raw_event_id, exc)
            return False
        except Exception as exc:  # noqa: BLE001
            self._failed_count += 1
            logger.error("Unexpected error publishing parsed event %s: %s", envelope.raw_event_id, exc)
            return False

    def metrics(self) -> dict:
        """Return basic producer metrics."""
        latencies = self._publish_latencies
        avg = sum(latencies) / len(latencies) if latencies else 0.0
        return {
            "bootstrap_servers": self.bootstrap_servers,
            "topic_raw_logs": self.topic_raw_logs,
            "topic_parsed_logs": self.topic_parsed_logs,
            "topic_normalized": self.topic_normalized,
            "topic_failed": self.topic_failed,
            "topic_schema_drift": self.topic_schema_drift,
            "published_count": len(latencies),
            "failed_count": self._failed_count,
            "avg_publish_latency_ms": round(avg * 1000, 2),
            "max_publish_latency_ms": round(max(latencies) * 1000, 2) if latencies else 0.0,
        }

    def publish_drift(self, drift_event: Any, key: str | None = None) -> bool:
        """Publish a schema drift event to the schema-drift-events topic.

        Args:
            drift_event: A DriftEvent instance with a to_dict() method.
            key: Optional message key. Defaults to drift_id.

        Returns:
            True if the message was successfully accepted by the broker.
        """
        start = time.monotonic()
        try:
            key = key or getattr(drift_event, "drift_id", None) or "drift"
            payload = drift_event.to_dict() if hasattr(drift_event, "to_dict") else drift_event
            import json
            value = json.dumps(payload, default=str).encode("utf-8")
            future = self.producer.send(
                self.topic_schema_drift,
                value=value,
                key=key.encode("utf-8") if isinstance(key, str) else key,
            )
            future.get(timeout=10)
            self._record_latency(start)
            logger.debug(
                "Published schema drift event drift_id=%s to topic=%s",
                key,
                self.topic_schema_drift,
            )
            return True
        except KafkaError as exc:
            self._failed_count += 1
            logger.error("Failed to publish drift event: %s", exc)
            return False
        except Exception as exc:  # noqa: BLE001
            self._failed_count += 1
            logger.error("Unexpected error publishing drift event: %s", exc)
            return False
