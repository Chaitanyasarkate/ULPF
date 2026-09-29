"""Temporary local raw-event sink for Phase 1 ingestion."""

from __future__ import annotations

import threading

from ulpf.common.models import EventEnvelope, ProcessingStatus

from .metrics import IngestionMetrics


class RawEventSink:
    """In-memory sink that stores raw event envelopes.

    This is a temporary Phase 1 local sink. Future phases will replace this
    with Kafka + MinIO + OpenSearch + Postgres storage.
    """

    def __init__(self, metrics: IngestionMetrics | None = None) -> None:
        self._lock = threading.Lock()
        self._events: list[EventEnvelope] = []
        self.metrics = metrics or IngestionMetrics()

    def store(self, envelope: EventEnvelope, method: str = "unknown") -> EventEnvelope:
        with self._lock:
            self._events.append(envelope)
        self.metrics.record_received(
            source_id=envelope.raw.source_id,
            fmt=envelope.raw.format,
            method=method,
        )
        return envelope

    def mark_success(self, envelope: EventEnvelope) -> None:
        envelope.processing_status = ProcessingStatus.RAW_STORED.value
        self.metrics.record_success()

    def mark_failed(self, envelope: EventEnvelope, error: str) -> None:
        envelope.processing_status = ProcessingStatus.FAILED.value
        self.metrics.record_failure()

    def all_events(self) -> list[EventEnvelope]:
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
