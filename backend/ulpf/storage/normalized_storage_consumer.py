"""Normalized Storage Consumer for ULPF Phase 5.

Consumes normalized events from Kafka and stores them in OpenSearch with PostgreSQL metadata.

Flow:
    Kafka (normalized-events) -> NormalizedStorageConsumer -> OpenSearch (searchable)
                                                |
                                                +-> PostgreSQL (metadata + references)

This consumer ensures:
    - Normalized events are indexed for search
    - Complete field preservation (ocsf, parsed_fields)
    - Lineage links to original raw events
    - Duplicate events are handled idempotently
    - Anomaly detection on stored events (Phase 10+)
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from ulpf.analytics.detector import AnomalyDetector
from ulpf.analytics.repository import AnomalyRepository
from ulpf.common.models import EventEnvelope, ProcessingStatus
from ulpf.config import get_settings
from ulpf.kafka.consumer import UlpfConsumer
from ulpf.storage.opensearch_adapter import OpenSearchAdapter, OpenSearchError
from ulpf.storage.postgres_adapter import PostgresAdapter

logger = logging.getLogger("ulpf.storage.normalized")


class NormalizedStorageError(Exception):
    """Base exception for normalized storage operations."""


class NormalizedStorageConsumer:
    """Kafka consumer that stores normalized events in OpenSearch with PostgreSQL metadata.

    Consumes from the normalized-events topic and:
    1. Indexes the normalized event in OpenSearch
    2. Creates metadata and storage references in PostgreSQL
    3. Links to original raw event for lineage
    4. Runs anomaly detection on the event
    """

    def __init__(
        self,
        bootstrap_servers: str | None = None,
        topic: str | None = None,
        group_id: str | None = None,
        opensearch_adapter: OpenSearchAdapter | None = None,
        postgres_adapter: PostgresAdapter | None = None,
        run_anomaly_detection: bool = True,
    ) -> None:
        settings = get_settings()

        self.bootstrap_servers = bootstrap_servers or settings.kafka.bootstrap_servers
        self.topic = topic or settings.kafka.topic_normalized
        self.group_id = group_id or f"{settings.kafka.group_id}-normalized-storage"
        self.run_anomaly_detection = run_anomaly_detection

        self.opensearch = opensearch_adapter or OpenSearchAdapter()
        self.postgres = postgres_adapter or PostgresAdapter()
        self._anomaly_detector = AnomalyDetector() if run_anomaly_detection else None
        self._anomaly_repo = AnomalyRepository() if run_anomaly_detection else None

        self._consumer: UlpfConsumer | None = None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._schema_initialized = False
        self._index_initialized = False

        self._indexed_count = 0
        self._error_count = 0
        self._skipped_count = 0
        self._anomalies_detected = 0

    async def _ensure_schema(self) -> None:
        """Initialize PostgreSQL schema if not already done."""
        if not self._schema_initialized:
            try:
                await self.postgres.initialize_schema()
                if self.run_anomaly_detection and self._anomaly_repo:
                    await self._anomaly_repo.initialize_schema()
                self._schema_initialized = True
            except Exception as exc:
                logger.error("Failed to initialize schema: %s", exc)
                raise

    async def _ensure_index(self) -> None:
        """Ensure OpenSearch index exists."""
        if not self._index_initialized:
            try:
                self.opensearch.ensure_index()
                self._index_initialized = True
            except Exception as exc:
                logger.error("Failed to ensure index: %s", exc)
                raise

    def _handle_envelope(self, envelope: EventEnvelope) -> None:
        """Synchronous handler for Kafka consumer callback."""
        asyncio.run(self._process_envelope(envelope))

    async def _process_envelope(self, envelope: EventEnvelope) -> None:
        """Process a single normalized event envelope.

        Args:
            envelope: The event envelope containing the normalized event.
        """
        if envelope.normalized is None:
            logger.warning(
                "Envelope has no normalized event: raw_event_id=%s",
                envelope.raw.raw_event_id,
            )
            return

        normalized = envelope.normalized
        event_id = normalized.event_id
        raw_event_id = normalized.raw_event_id

        try:
            await self._ensure_schema()
            await self._ensure_index()

            index_name = self.opensearch.index_normalized_event(normalized)

            metadata_stored = await self.postgres.insert_event_metadata(
                envelope,
                processing_status=ProcessingStatus.STORED.value,
            )

            if metadata_stored:
                await self.postgres.insert_normalized_event_metadata(
                    normalized,
                    index_name=index_name,
                )

            # Run anomaly detection if enabled
            if self.run_anomaly_detection and self._anomaly_detector:
                # Use a fresh repository per event — asyncpg pools are bound to
                # a single event loop, which closes between Kafka messages.
                anomaly_repo = AnomalyRepository()
                try:
                    await anomaly_repo.initialize_schema()
                    result = await self._anomaly_detector.detect(normalized, repo=anomaly_repo)
                    for anomaly in result.anomalies:
                        await anomaly_repo.insert_anomaly(anomaly)
                        self._anomalies_detected += 1
                        logger.info(
                            "Anomaly detected: anomaly_id=%s rule=%s severity=%s event_id=%s",
                            anomaly.anomaly_id,
                            anomaly.rule_id,
                            anomaly.severity.value,
                            event_id,
                        )
                except Exception as exc:
                    logger.warning("Anomaly detection failed for event %s: %s", event_id, exc)
                finally:
                    await anomaly_repo.close()

            self._indexed_count += 1
            logger.info(
                "Indexed normalized event: event_id=%s raw_event_id=%s index=%s",
                event_id,
                raw_event_id,
                index_name,
            )

        except OpenSearchError as exc:
            self._error_count += 1
            logger.error(
                "OpenSearch indexing error: event_id=%s error=%s",
                event_id,
                exc,
            )

        except Exception as exc:
            self._error_count += 1
            logger.error(
                "Unexpected error indexing event: event_id=%s error=%s",
                event_id,
                exc,
            )

    def _create_consumer(self) -> UlpfConsumer:
        """Create the Kafka consumer."""
        return UlpfConsumer(
            bootstrap_servers=self.bootstrap_servers,
            topic=self.topic,
            group_id=self.group_id,
        )

    def start(self, poll_timeout: float = 1.0) -> None:
        """Start the normalized storage consumer in a background thread.

        Args:
            poll_timeout: Kafka poll timeout in seconds.
        """
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Normalized storage consumer already running")
            return

        self._stop_event.clear()
        self._consumer = self._create_consumer()
        self._thread = threading.Thread(
            target=self._run,
            args=(poll_timeout,),
            daemon=True,
        )
        self._thread.start()

        logger.info(
            "Normalized storage consumer started: topic=%s group=%s",
            self.topic,
            self.group_id,
        )

    def _run(self, poll_timeout: float) -> None:
        """Main consumer loop."""
        try:
            if self._consumer:
                self._consumer.consume(self._handle_envelope, poll_timeout=poll_timeout)
        finally:
            self._cleanup()

    def _cleanup(self) -> None:
        """Clean up resources."""
        if self._consumer:
            self._consumer.stop()
        self.postgres.close()
        if self._anomaly_repo:
            asyncio.run(self._anomaly_repo.close())
        logger.info(
            "Normalized storage consumer stopped: indexed=%d errors=%d skipped=%d anomalies=%d",
            self._indexed_count,
            self._error_count,
            self._skipped_count,
            self._anomalies_detected,
        )

    def stop(self) -> None:
        """Stop the normalized storage consumer."""
        self._stop_event.set()
        if self._consumer:
            self._consumer.stop()

    def metrics(self) -> dict[str, Any]:
        """Get consumer metrics."""
        metrics = {
            "topic": self.topic,
            "group_id": self.group_id,
            "indexed_count": self._indexed_count,
            "error_count": self._error_count,
            "skipped_count": self._skipped_count,
        }
        if self.run_anomaly_detection:
            metrics["anomalies_detected"] = self._anomalies_detected
        return metrics


def start_normalized_storage_consumer(
    bootstrap_servers: str | None = None,
    topic: str | None = None,
    group_id: str | None = None,
    run_anomaly_detection: bool = True,
) -> NormalizedStorageConsumer:
    """Start a normalized storage consumer in a background thread.

    Convenience function for easy startup.

    Args:
        bootstrap_servers: Kafka broker addresses.
        topic: Topic to consume.
        group_id: Consumer group id.
        run_anomaly_detection: Whether to run anomaly detection.

    Returns:
        The started consumer instance.
    """
    consumer = NormalizedStorageConsumer(
        bootstrap_servers=bootstrap_servers,
        topic=topic,
        group_id=group_id,
        run_anomaly_detection=run_anomaly_detection,
    )
    consumer.start()
    return consumer