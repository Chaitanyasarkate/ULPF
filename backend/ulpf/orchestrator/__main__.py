"""ULPF Unified Pipeline Runner.

Run with:  python -m ulpf.orchestrator

This module orchestrates all ULPF pipeline services:
1. Kafka topics initialization
2. Parser Engine (raw-logs -> parsed-logs)
3. Normalizer Engine (parsed-logs -> normalized-events)
4. Raw Storage Consumer (raw-logs -> MinIO + PostgreSQL)
5. Normalized Storage Consumer (normalized-events -> OpenSearch + PostgreSQL)

The runner handles:
- Startup in correct dependency order
- Graceful shutdown on SIGINT/SIGTERM
- Health monitoring
- Clean resource cleanup
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
import threading
from typing import Any

from ulpf.common.logging import configure_root, get_logger
from ulpf.config import get_settings
from ulpf.lineage.service import LineageService

log = get_logger("ulpf.orchestrator")


class PipelineRunner:
    """Orchestrates all ULPF pipeline services."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._running = False
        self._shutdown_event = threading.Event()

        self._parser_engine: Any = None
        self._normalizer_engine: Any = None
        self._raw_storage_consumer: Any = None
        self._normalized_storage_consumer: Any = None
        self._lineage_service: LineageService | None = None

    def _init_kafka_topics(self) -> None:
        """Initialize Kafka topics."""
        log.info("Initializing Kafka topics...")
        try:
            from ulpf.kafka.topics import ensure_topics
            ensure_topics()
            log.info("Kafka topics initialized successfully")
        except Exception as exc:
            log.error("Failed to initialize Kafka topics: %s", exc)
            raise

    def _init_lineage_schema(self) -> None:
        """Initialize PostgreSQL lineage schema and create lineage service."""
        log.info("Initializing PostgreSQL lineage schema...")
        try:
            from ulpf.lineage.repository import LineageRepository
            repo = LineageRepository()
            repo.initialize_schema()
            log.info("PostgreSQL lineage schema initialized successfully")
        except Exception as exc:
            log.error("Failed to initialize lineage schema: %s", exc)
            raise

    def _init_lineage_service(self) -> None:
        """Initialize the lineage service for traceability."""
        log.info("Initializing Lineage Service...")
        try:
            self._lineage_service = LineageService()
            self._lineage_service.initialize()
            log.info("Lineage Service initialized successfully")
        except Exception as exc:
            log.error("Failed to initialize Lineage Service: %s", exc)
            raise

    def _init_parser_engine(self) -> None:
        """Initialize and start the parser engine."""
        log.info("Starting Parser Engine...")
        try:
            from ulpf.parsers.engine import ParserEngine
            self._parser_engine = ParserEngine(lineage_service=self._lineage_service)
            self._parser_engine.start()
            log.info("Parser Engine started (consuming from %s)", self._parser_engine.topic_raw_logs)
        except Exception as exc:
            log.error("Failed to start Parser Engine: %s", exc)
            raise

    def _init_normalizer_engine(self) -> None:
        """Initialize and start the normalizer engine."""
        log.info("Starting Normalizer Engine...")
        try:
            from ulpf.normalizer.engine import NormalizerEngine
            self._normalizer_engine = NormalizerEngine(lineage_service=self._lineage_service)
            self._normalizer_engine.start()
            log.info("Normalizer Engine started (consuming from %s)", self._normalizer_engine.topic_parsed_logs)
        except Exception as exc:
            log.error("Failed to start Normalizer Engine: %s", exc)
            raise

    def _init_raw_storage_consumer(self) -> None:
        """Initialize and start the raw storage consumer."""
        log.info("Starting Raw Storage Consumer...")
        try:
            from ulpf.storage.raw_storage_consumer import RawStorageConsumer
            self._raw_storage_consumer = RawStorageConsumer()
            self._raw_storage_consumer.start()
            log.info("Raw Storage Consumer started (consuming from %s)", self._raw_storage_consumer.topic)
        except Exception as exc:
            log.error("Failed to start Raw Storage Consumer: %s", exc)
            raise

    def _init_normalized_storage_consumer(self) -> None:
        """Initialize and start the normalized storage consumer."""
        log.info("Starting Normalized Storage Consumer...")
        try:
            from ulpf.storage.normalized_storage_consumer import NormalizedStorageConsumer
            self._normalized_storage_consumer = NormalizedStorageConsumer()
            self._normalized_storage_consumer.start()
            log.info("Normalized Storage Consumer started (consuming from %s)", self._normalized_storage_consumer.topic)
        except Exception as exc:
            log.error("Failed to start Normalized Storage Consumer: %s", exc)
            raise

    def start(self) -> None:
        """Start all pipeline services in the correct order."""
        log.info("=" * 60)
        log.info("ULPF Pipeline Runner starting...")
        log.info("=" * 60)
        log.info("Configuration:")
        log.info("  Kafka: %s", self.settings.kafka.bootstrap_servers)
        log.info("  MinIO: %s", self.settings.minio.endpoint)
        log.info("  OpenSearch: %s", self.settings.opensearch.host)
        log.info("  PostgreSQL: %s:%s/%s", self.settings.postgres.host, self.settings.postgres.port, self.settings.postgres.db)
        log.info("=" * 60)

        self._running = True

        try:
            self._init_kafka_topics()
            log.info("-" * 40)

            self._init_lineage_schema()
            log.info("-" * 40)

            self._init_lineage_service()
            log.info("-" * 40)

            self._init_parser_engine()
            log.info("-" * 40)

            self._init_normalizer_engine()
            log.info("-" * 40)

            self._init_raw_storage_consumer()
            log.info("-" * 40)

            self._init_normalized_storage_consumer()
            log.info("-" * 40)

            log.info("=" * 60)
            log.info("ULPF Pipeline Runner started successfully!")
            log.info("All services running:")
            log.info("  - Parser Engine: %s -> %s", self.settings.kafka.topic_raw_logs, self.settings.kafka.topic_parsed_logs)
            log.info("  - Normalizer Engine: %s -> %s", self.settings.kafka.topic_parsed_logs, self.settings.kafka.topic_normalized)
            log.info("  - Raw Storage: %s -> MinIO + PostgreSQL", self.settings.kafka.topic_raw_logs)
            log.info("  - Normalized Storage: %s -> OpenSearch + PostgreSQL", self.settings.kafka.topic_normalized)
            log.info("=" * 60)
            log.info("Press Ctrl+C to stop...")

        except Exception as exc:
            log.error("Pipeline startup failed: %s", exc)
            self.stop()
            raise

    def stop(self) -> None:
        """Stop all pipeline services gracefully."""
        if not self._running:
            return

        log.info("=" * 60)
        log.info("ULPF Pipeline Runner shutting down...")
        log.info("=" * 60)

        if self._normalized_storage_consumer:
            log.info("Stopping Normalized Storage Consumer...")
            try:
                self._normalized_storage_consumer.stop()
                log.info("Normalized Storage Consumer stopped")
            except Exception as exc:
                log.warning("Error stopping Normalized Storage Consumer: %s", exc)

        if self._raw_storage_consumer:
            log.info("Stopping Raw Storage Consumer...")
            try:
                self._raw_storage_consumer.stop()
                log.info("Raw Storage Consumer stopped")
            except Exception as exc:
                log.warning("Error stopping Raw Storage Consumer: %s", exc)

        if self._normalizer_engine:
            log.info("Stopping Normalizer Engine...")
            try:
                self._normalizer_engine.stop()
                log.info("Normalizer Engine stopped")
            except Exception as exc:
                log.warning("Error stopping Normalizer Engine: %s", exc)

        if self._parser_engine:
            log.info("Stopping Parser Engine...")
            try:
                self._parser_engine.stop()
                log.info("Parser Engine stopped")
            except Exception as exc:
                log.warning("Error stopping Parser Engine: %s", exc)

        self._running = False
        log.info("=" * 60)
        log.info("ULPF Pipeline Runner stopped")
        log.info("=" * 60)

    def is_running(self) -> bool:
        """Check if the pipeline is running."""
        return self._running

    def get_metrics(self) -> dict[str, Any]:
        """Get metrics from all running services."""
        metrics: dict[str, Any] = {
            "running": self._running,
        }

        if self._parser_engine:
            metrics["parser_engine"] = {
                "topic": self._parser_engine.topic_raw_logs,
                "group_id": self._parser_engine.group_id,
            }

        if self._normalizer_engine:
            metrics["normalizer_engine"] = {
                "topic": self._normalizer_engine.topic_parsed_logs,
                "group_id": self._normalizer_engine.group_id,
            }

        if self._raw_storage_consumer:
            metrics["raw_storage"] = self._raw_storage_consumer.metrics()

        if self._normalized_storage_consumer:
            metrics["normalized_storage"] = self._normalized_storage_consumer.metrics()

        return metrics


_runner: PipelineRunner | None = None


def _signal_handler(signum: int, frame: Any) -> None:
    """Handle shutdown signals."""
    log.info("Received signal %d, initiating shutdown...", signum)
    if _runner:
        _runner.stop()
    sys.exit(0)


def main() -> int:
    """Main entry point for the pipeline runner."""
    configure_root()

    global _runner

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    _runner = PipelineRunner()

    try:
        _runner.start()

        while _runner.is_running():
            try:
                import time
                time.sleep(1)
            except KeyboardInterrupt:
                break

    except Exception as exc:
        log.error("Pipeline runner error: %s", exc)
        return 1
    finally:
        if _runner:
            _runner.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
