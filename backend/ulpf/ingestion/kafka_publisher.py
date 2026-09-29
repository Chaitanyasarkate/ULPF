"""Kafka publisher helper for ULPF ingestion layer."""

from __future__ import annotations

import logging

from ulpf.common.models import EventEnvelope
from ulpf.config import get_settings

logger = logging.getLogger("ulpf.ingestion.kafka")

try:
    from ulpf.kafka.producer import UlpfProducer

    _KAFKA_PRODUCER_AVAILABLE = True
except Exception:  # noqa: BLE001 pragma: no cover - optional dependency guard
    _KAFKA_PRODUCER_AVAILABLE = False


class KafkaPublisher:
    """Publishes ingested events to Kafka when enabled.

    This wrapper allows the ingestion layer to remain agnostic about whether
    Kafka is enabled. When disabled, all methods become no-ops.
    """

    def __init__(self) -> None:
        settings = get_settings()
        self.enabled = settings.kafka.enabled and _KAFKA_PRODUCER_AVAILABLE
        self._producer: UlpfProducer | None = None

    @property
    def producer(self) -> UlpfProducer | None:
        if not self.enabled:
            return None
        if self._producer is None:
            self._producer = UlpfProducer()
        return self._producer

    def publish(self, envelope: EventEnvelope) -> bool:
        """Publish an event envelope to Kafka.

        Returns:
            True if published successfully or Kafka is disabled.
            False if publishing failed.
        """
        if not self.enabled or self.producer is None:
            return True
        try:
            return self.producer.publish_raw(envelope)
        except Exception as exc:  # noqa: BLE001
            logger.error("Kafka publish failed for raw_event_id=%s: %s", envelope.raw_event_id, exc)
            return False

    def close(self) -> None:
        if self._producer is not None:
            self._producer.close()
            self._producer = None
