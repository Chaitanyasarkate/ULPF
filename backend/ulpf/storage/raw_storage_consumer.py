"""Raw Storage Consumer for ULPF Phase 5.

Consumes raw events from Kafka and stores them in MinIO with PostgreSQL metadata.

Flow:
    Kafka (raw-logs) -> RawStorageConsumer -> MinIO (raw vault)
                                        |
                                        +-> PostgreSQL (metadata + references)

This consumer ensures:
    - Original raw payloads are preserved losslessly
    - SHA-256 integrity is maintained
    - Metadata enables lineage resolution
    - Duplicate events are handled idempotently
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from ulpf.common.models import EventEnvelope, ProcessingStatus
from ulpf.config import get_settings
from ulpf.kafka.consumer import UlpfConsumer
from ulpf.storage.minio_adapter import (
    IntegrityVerificationError,
    MinIOAdapter,
    MinIOError,
    ObjectConflictError,
)
from ulpf.storage.postgres_adapter import PostgresAdapter

logger = logging.getLogger("ulpf.storage.raw")


class RawStorageError(Exception):
    """Base exception for raw storage operations."""


class RawStorageConsumer:
    """Kafka consumer that stores raw events in MinIO with PostgreSQL metadata.

    Consumes from the raw-logs topic and:
    1. Stores the original raw payload in MinIO
    2. Creates metadata and storage references in PostgreSQL
    3. Handles duplicates idempotently
    """

    def __init__(
        self,
        bootstrap_servers: str | None = None,
        topic: str | None = None,
        group_id: str | None = None,
        minio_adapter: MinIOAdapter | None = None,
        postgres_adapter: PostgresAdapter | None = None,
    ) -> None:
        settings = get_settings()

        self.bootstrap_servers = bootstrap_servers or settings.kafka.bootstrap_servers
        self.topic = topic or settings.kafka.topic_raw_logs
        self.group_id = group_id or f"{settings.kafka.group_id}-raw-storage"

        self.minio = minio_adapter or MinIOAdapter()
        self.postgres = postgres_adapter or PostgresAdapter()

        self._consumer: UlpfConsumer | None = None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._schema_initialized = False

        self._stored_count = 0
        self._error_count = 0
        self._skipped_count = 0

    async def _ensure_schema(self) -> None:
        """Initialize PostgreSQL schema if not already done."""
        if not self._schema_initialized:
            try:
                await self.postgres.initialize_schema()
                self._schema_initialized = True
            except Exception as exc:
                logger.error("Failed to initialize schema: %s", exc)
                raise

    async def _ensure_bucket(self) -> None:
        """Ensure MinIO bucket exists."""
        try:
            await self.minio.ensure_bucket_exists()
        except Exception as exc:
            logger.error("Failed to ensure bucket: %s", exc)
            raise

    def _handle_envelope(self, envelope: EventEnvelope) -> None:
        """Synchronous handler for Kafka consumer callback."""
        asyncio.run(self._process_envelope(envelope))

    async def _process_envelope(self, envelope: EventEnvelope) -> None:
        """Process a single raw event envelope.

        Args:
            envelope: The raw event envelope from Kafka.
        """
        raw_event_id = envelope.raw.raw_event_id

        try:
            await self._ensure_schema()
            await self._ensure_bucket()

            object_key = await self.minio.upload_envelope(
                envelope,
                skip_if_exists=True,
            )

            metadata_stored = await self.postgres.insert_event_metadata(
                envelope,
                processing_status=ProcessingStatus.RAW_STORED.value,
            )

            if metadata_stored and envelope.sha256:
                await self.postgres.insert_raw_object_metadata(
                    raw_event_id=raw_event_id,
                    object_key=object_key,
                    bucket=self.minio.bucket,
                    sha256=envelope.sha256,
                    size_bytes=envelope.raw.original_payload_bytes,
                )

            self._stored_count += 1
            logger.info(
                "Stored raw event: raw_event_id=%s key=%s",
                raw_event_id,
                object_key,
            )

        except ObjectConflictError as exc:
            self._skipped_count += 1
            logger.info(
                "Skipped duplicate (conflict): raw_event_id=%s reason=%s",
                raw_event_id,
                exc,
            )

        except IntegrityVerificationError as exc:
            self._error_count += 1
            logger.error(
                "Integrity verification failed: raw_event_id=%s error=%s",
                raw_event_id,
                exc,
            )

        except MinIOError as exc:
            self._error_count += 1
            logger.error(
                "MinIO storage error: raw_event_id=%s error=%s",
                raw_event_id,
                exc,
            )

        except Exception as exc:
            self._error_count += 1
            logger.error(
                "Unexpected error processing raw event: raw_event_id=%s error=%s",
                raw_event_id,
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
        """Start the raw storage consumer in a background thread.

        Args:
            poll_timeout: Kafka poll timeout in seconds.
        """
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Raw storage consumer already running")
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
            "Raw storage consumer started: topic=%s group=%s",
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
        logger.info(
            "Raw storage consumer stopped: stored=%d errors=%d skipped=%d",
            self._stored_count,
            self._error_count,
            self._skipped_count,
        )

    def stop(self) -> None:
        """Stop the raw storage consumer."""
        self._stop_event.set()
        if self._consumer:
            self._consumer.stop()

    def metrics(self) -> dict[str, Any]:
        """Get consumer metrics."""
        return {
            "topic": self.topic,
            "group_id": self.group_id,
            "stored_count": self._stored_count,
            "error_count": self._error_count,
            "skipped_count": self._skipped_count,
        }


def start_raw_storage_consumer(
    bootstrap_servers: str | None = None,
    topic: str | None = None,
    group_id: str | None = None,
) -> RawStorageConsumer:
    """Start a raw storage consumer in a background thread.

    Convenience function for easy startup.

    Args:
        bootstrap_servers: Kafka broker addresses.
        topic: Topic to consume.
        group_id: Consumer group id.

    Returns:
        The started consumer instance.
    """
    consumer = RawStorageConsumer(
        bootstrap_servers=bootstrap_servers,
        topic=topic,
        group_id=group_id,
    )
    consumer.start()
    return consumer
