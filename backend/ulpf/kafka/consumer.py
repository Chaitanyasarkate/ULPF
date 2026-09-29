"""Kafka consumer service for ULPF."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from ulpf.common.models import EventEnvelope
from ulpf.config import get_settings

logger = logging.getLogger("ulpf.kafka.consumer")

try:
    from kafka import KafkaConsumer
    from kafka.errors import KafkaError

    _KAFKA_CONSUMER_AVAILABLE = True
except Exception:  # noqa: BLE001  # pragma: no cover - optional dependency guard
    _KAFKA_CONSUMER_AVAILABLE = False


class UlpfConsumer:
    """Reusable Kafka consumer for ULPF event envelopes.

    Consumes messages from the configured topic (default ``raw-logs``),
    deserializes them into ``EventEnvelope`` instances, validates basic
    integrity, and dispatches them to a user-provided handler.
    """

    def __init__(
        self,
        bootstrap_servers: str | None = None,
        topic: str | None = None,
        group_id: str | None = None,
        auto_offset_reset: str | None = None,
        seek_to_end: bool = False,
    ) -> None:
        settings = get_settings()
        self.bootstrap_servers = bootstrap_servers or settings.kafka.bootstrap_servers
        self.topic = topic or settings.kafka.topic_raw_logs
        self.group_id = group_id or settings.kafka.group_id
        self.auto_offset_reset = auto_offset_reset or settings.kafka.auto_offset_reset
        self._seek_to_end = seek_to_end

        self._consumer: Any = None
        self._stop_event = threading.Event()
        self._consumed_count: int = 0
        self._error_count: int = 0

    @property
    def consumer(self) -> Any:
        if self._consumer is None:
            if not _KAFKA_CONSUMER_AVAILABLE:
                raise RuntimeError("kafka-python is not installed")
            self._consumer = KafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.group_id,
                auto_offset_reset=self.auto_offset_reset,
                value_deserializer=lambda v: v,
                key_deserializer=lambda v: v.decode("utf-8") if v else None,
                enable_auto_commit=not self._seek_to_end,
                auto_commit_interval_ms=5000,
                consumer_timeout_ms=1000,
            )
            if self._seek_to_end:
                for _ in range(10):
                    self._consumer.poll(timeout_ms=1000)
                    if self._consumer.assignment():
                        break
                self._consumer.seek_to_end()
                for tp in self._consumer.assignment():
                    self._consumer.position(tp)
            logger.info(
                "Kafka consumer started topic=%s group=%s servers=%s",
                self.topic,
                self.group_id,
                self.bootstrap_servers,
            )
        return self._consumer

    def _validate_envelope(self, envelope: EventEnvelope) -> bool:
        """Validate basic envelope integrity."""
        if not envelope.raw_event_id:
            logger.warning("Consumed envelope missing raw_event_id")
            return False
        if not envelope.raw.payload:
            logger.warning("Consumed envelope missing payload raw_event_id=%s", envelope.raw_event_id)
            return False
        return True

    def consume(
        self,
        handler: Callable[[EventEnvelope], None],
        poll_timeout: float = 1.0,
        max_idle_iterations: int = 0,
        max_messages: int = 0,
    ) -> None:
        """Consume messages and dispatch them to ``handler``.

        Args:
            handler: Callable that receives a validated ``EventEnvelope``.
            poll_timeout: Maximum time to block on each ``poll()`` call.
            max_idle_iterations: If > 0, stop the consumer loop after this
                many consecutive ``poll()`` calls return no records.
                Useful for one-shot test scenarios.
            max_messages: If > 0, stop the consumer loop after this many
                messages have been dispatched to ``handler``.
        """
        self._stop_event.clear()
        logger.info("Consumer loop started for topic=%s", self.topic)

        idle_count = 0
        messages_consumed = 0
        try:
            while not self._stop_event.is_set():
                try:
                    messages = self.consumer.poll(timeout_ms=int(poll_timeout * 1000))
                except StopIteration:
                    break
                except KafkaError as exc:
                    logger.error("Kafka poll error: %s", exc)
                    self._error_count += 1
                    time.sleep(0.5)
                    continue
                except Exception as exc:  # noqa: BLE001
                    logger.error("Unexpected consumer poll error: %s", exc)
                    self._error_count += 1
                    time.sleep(0.5)
                    continue

                if not messages:
                    idle_count += 1
                    if max_idle_iterations > 0 and idle_count >= max_idle_iterations:
                        logger.info(
                            "Consumer stopping after %d idle poll iterations on topic=%s",
                            idle_count,
                            self.topic,
                        )
                        break
                    continue
                idle_count = 0

                for topic_partition, records in messages.items():
                    for record in records:
                        if self._stop_event.is_set():
                            break
                        try:
                            envelope = EventEnvelope.from_kafka_value(record.value)
                        except Exception as exc:  # noqa: BLE001
                            logger.warning(
                                "Malformed Kafka message on topic=%s partition=%s offset=%s: %s",
                                topic_partition.topic,
                                topic_partition.partition,
                                record.offset,
                                exc,
                            )
                            self._error_count += 1
                            continue

                        if not self._validate_envelope(envelope):
                            self._error_count += 1
                            continue

                        try:
                            handler(envelope)
                            self._consumed_count += 1
                            messages_consumed += 1
                            logger.debug(
                                "Consumed event raw_event_id=%s offset=%s",
                                envelope.raw_event_id,
                                record.offset,
                            )
                            if max_messages > 0 and messages_consumed >= max_messages:
                                logger.info(
                                    "Consumer stopping after %d messages on topic=%s",
                                    messages_consumed,
                                    self.topic,
                                )
                                self._stop_event.set()
                                break
                        except Exception as exc:  # noqa: BLE001
                            logger.error(
                                "Handler error for raw_event_id=%s: %s",
                                envelope.raw_event_id,
                                exc,
                            )
                            self._error_count += 1
        finally:
            self.stop()

    def stop(self) -> None:
        """Signal the consumer loop to stop and close the consumer."""
        self._stop_event.set()
        if self._consumer is not None:
            try:
                self._consumer.close()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Error closing Kafka consumer: %s", exc)
            finally:
                self._consumer = None
        logger.info(
            "Kafka consumer stopped consumed=%d errors=%d",
            self._consumed_count,
            self._error_count,
        )

    def metrics(self) -> dict:
        """Return basic consumer metrics."""
        return {
            "bootstrap_servers": self.bootstrap_servers,
            "topic": self.topic,
            "group_id": self.group_id,
            "consumed_count": self._consumed_count,
            "error_count": self._error_count,
        }


def start_consumer_thread(
    bootstrap_servers: str | None = None,
    topic: str | None = None,
    group_id: str | None = None,
    handler: Callable[[EventEnvelope], None] | None = None,
) -> UlpfConsumer:
    """Start a consumer in a background daemon thread.

    Args:
        bootstrap_servers: Kafka broker addresses.
        topic: Topic to consume.
        group_id: Consumer group id.
        handler: Optional default handler. Can also be passed to ``consume()``.

    Returns:
        The started ``UlpfConsumer`` instance.
    """
    consumer = UlpfConsumer(
        bootstrap_servers=bootstrap_servers,
        topic=topic,
        group_id=group_id,
    )
    thread = threading.Thread(
        target=consumer.consume,
        args=(handler,) if handler else (lambda e: None,),
        daemon=True,
    )
    thread.start()
    return consumer
