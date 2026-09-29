"""Parser engine for ULPF Phase 3."""

from __future__ import annotations

import logging
import threading

from ulpf.common.models import (
    EventEnvelope,
    EventError,
    ParsedEvent,
    ProcessingStatus,
    SourceType,
)
from ulpf.config import get_settings
from ulpf.kafka.consumer import UlpfConsumer
from ulpf.kafka.producer import UlpfProducer
from ulpf.lineage.service import LineageService
from ulpf.parsers.base import BaseParser
from ulpf.parsers.cef import IDSCEFParser
from ulpf.parsers.detection import detect_format, detect_source_type
from ulpf.parsers.json import RouterJsonParser
from ulpf.parsers.registry import ParserRegistry
from ulpf.parsers.syslog import FirewallSyslogParser

logger = logging.getLogger("ulpf.parsers.engine")


class ParserEngine:
    """Core parser engine that consumes raw events from Kafka and produces
    parsed events or failed events.

    The engine:
    1. Consumes from ``raw-logs``.
    2. Detects format and source type (falling back to metadata).
    3. Looks up the appropriate parser from the registry.
    4. Parses the event into a ``ParsedEvent``.
    5. Publishes to ``parsed-logs`` on success or ``failed-events`` on failure.
    """

    def __init__(
        self,
        registry: ParserRegistry | None = None,
        bootstrap_servers: str | None = None,
        topic_raw_logs: str | None = None,
        topic_parsed_logs: str | None = None,
        topic_failed: str | None = None,
        group_id: str | None = None,
        lineage_service: LineageService | None = None,
        enable_schema_drift: bool = True,
    ) -> None:
        settings = get_settings()
        self.registry = registry or ParserRegistry()
        self._register_default_parsers()
        self.lineage_service = lineage_service
        self.enable_schema_drift = enable_schema_drift

        self.bootstrap_servers = bootstrap_servers or settings.kafka.bootstrap_servers
        self.topic_raw_logs = topic_raw_logs or settings.kafka.topic_raw_logs
        self.topic_parsed_logs = topic_parsed_logs or settings.kafka.topic_parsed_logs
        self.topic_failed = topic_failed or settings.kafka.topic_failed
        self.group_id = group_id or settings.kafka.group_id

        self._producer = UlpfProducer(
            bootstrap_servers=self.bootstrap_servers,
            topic_raw_logs=self.topic_raw_logs,
            topic_parsed_logs=self.topic_parsed_logs,
            topic_failed=self.topic_failed,
        )
        self._consumer = UlpfConsumer(
            bootstrap_servers=self.bootstrap_servers,
            topic=self.topic_raw_logs,
            group_id=self.group_id,
        )
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        # Schema drift detector (optional, runs in background thread)
        self._drift_detector = None
        if self.enable_schema_drift:
            try:
                from ulpf.schema.detector import SchemaDriftDetector
                self._drift_detector = SchemaDriftDetector(
                    drift_publisher=self._producer,
                )
                logger.info("Schema drift detector initialized")
            except Exception as exc:
                logger.warning("Failed to initialize schema drift detector: %s", exc)

    def _register_default_parsers(self) -> None:
        self.registry.register(FirewallSyslogParser())
        self.registry.register(RouterJsonParser())
        self.registry.register(IDSCEFParser())

    def _select_parser(self, envelope: EventEnvelope) -> BaseParser | None:
        fmt = detect_format(envelope.raw.payload, envelope.raw.format)
        source_type = detect_source_type(envelope.raw.source_type, envelope.raw.payload)

        if fmt and fmt != "unknown":
            envelope.raw.format = fmt
        if source_type and source_type != SourceType.UNKNOWN.value:
            envelope.raw.source_type = source_type

        parser = self.registry.lookup(envelope)
        if parser is not None:
            logger.debug(
                "Selected parser parser_id=%s for raw_event_id=%s format=%s source_type=%s",
                parser.parser_id,
                envelope.raw_event_id,
                envelope.raw.format,
                envelope.raw.source_type,
            )
            return parser

        logger.warning(
            "No parser found for raw_event_id=%s format=%s source_type=%s",
            envelope.raw_event_id,
            envelope.raw.format,
            envelope.raw.source_type,
        )
        return None

    def _parse_envelope(self, envelope: EventEnvelope) -> ParsedEvent | None:
        parser = self._select_parser(envelope)
        if parser is None:
            return None
        envelope.parser_id = parser.parser_id
        envelope.parser_version = parser.parser_version
        return parser.parse(envelope)

    def _publish_parsed(self, envelope: EventEnvelope, parsed: ParsedEvent) -> None:
        envelope.parsed = parsed
        envelope.processing_status = ProcessingStatus.PARSED.value
        self._producer.publish_parsed(envelope, key=parsed.event_id)
        logger.debug(
            "Queued parsed event raw_event_id=%s parser_id=%s",
            envelope.raw_event_id,
            envelope.parser_id,
        )
        # Record lineage: raw_event_id -> parsed_event_id
        if self.lineage_service:
            logger.debug("Recording parse lineage for raw_event_id=%s", envelope.raw_event_id)
            try:
                import traceback
                self.lineage_service.record_parsing_lineage(envelope)
                logger.info("Recorded parse lineage: raw=%s -> parsed=%s",
                           envelope.raw.raw_event_id, envelope.parsed.event_id)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to record parse lineage: raw_event_id=%s error=%s\n%s",
                              envelope.raw_event_id, exc, traceback.format_exc())

    def _publish_failed(self, envelope: EventEnvelope, error: EventError) -> None:
        envelope.processing_status = ProcessingStatus.FAILED.value
        envelope.error = error
        failed_envelope = EventEnvelope(
            raw=envelope.raw,
            parsed=envelope.parsed,
            sha256=envelope.sha256,
            previous_hash=envelope.previous_hash,
            current_hash=envelope.current_hash,
            processing_status=ProcessingStatus.FAILED.value,
            error=error,
            parser_id=envelope.parser_id,
            parser_version=envelope.parser_version,
            schema_version=envelope.schema_version,
        )
        self._producer.publish_failed(failed_envelope, key=envelope.raw_event_id)
        logger.warning(
            "Published failed event raw_event_id=%s error=%s",
            envelope.raw_event_id,
            error.message,
        )

    def _handle_envelope(self, envelope: EventEnvelope) -> None:
        try:
            parsed = self._parse_envelope(envelope)
        except Exception as exc:  # noqa: BLE001
            error = EventError.from_exception("parser", "E_PARSE_001", exc)
            self._publish_failed(envelope, error)
            return

        if parsed is None:
            error = EventError(
                stage="parser",
                code="E_NO_PARSER",
                message=f"No parser available for format={envelope.raw.format} source_type={envelope.raw.source_type}",
            )
            self._publish_failed(envelope, error)
            return

        # Run schema drift detection on the parsed event (fully synchronous)
        if self._drift_detector and envelope.parsed:
            try:
                self._drift_detector.detect_and_publish(envelope)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Schema drift detection failed for raw_event_id=%s: %s",
                               envelope.raw_event_id, exc)

        try:
            self._publish_parsed(envelope, parsed)
        except Exception as exc:  # noqa: BLE001
            error = EventError.from_exception("publisher", "E_PUBLISH_001", exc)
            self._publish_failed(envelope, error)

    async def _run_schema_drift(self, envelope: EventEnvelope) -> None:
        """Run schema drift detection and publish drift events if found."""
        if self._drift_detector is None:
            return
        try:
            result = await self._drift_detector.detect_and_publish(envelope)
            if result and result.drift_detected:
                logger.info(
                    "Schema drift detected: source=%s event=%s types=%s severity=%s",
                    result.source_id,
                    result.event_id,
                    result.drift_types,
                    result.severity,
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Schema drift detection error: %s", exc)

    def start(self, poll_timeout: float = 1.0) -> None:
        """Start the parser engine in a background daemon thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            args=(poll_timeout,),
            daemon=True,
        )
        self._thread.start()
        logger.info("Parser engine started group=%s topic=%s", self.group_id, self.topic_raw_logs)

    def _run(self, poll_timeout: float) -> None:
        self._consumer.consume(self._handle_envelope, poll_timeout=poll_timeout)

    def stop(self) -> None:
        """Stop the parser engine and release resources."""
        self._stop_event.set()
        self._consumer.stop()
        self._producer.close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        logger.info("Parser engine stopped")
