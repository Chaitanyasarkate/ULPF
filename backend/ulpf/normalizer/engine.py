"""Normalizer engine for ULPF Phase 4."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from ulpf.common.models import (
    EventEnvelope,
    EventError,
    NormalizedEvent,
    ProcessingStatus,
)
from ulpf.config import get_settings
from ulpf.kafka.consumer import UlpfConsumer
from ulpf.kafka.producer import UlpfProducer
from ulpf.lineage.service import LineageService
from ulpf.normalizer.base import BaseNormalizer
from ulpf.normalizer.mappings import (
    normalize_action,
    normalize_severity,
    normalize_timestamp,
)
from ulpf.normalizer.validation import validate_ip, validate_port, validate_protocol

logger = logging.getLogger("ulpf.normalizer.engine")

SCHEMA_VERSION = "1.0.0"


def _set_nested(d: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    for part in parts[:-1]:
        d = d.setdefault(part, {})
    d[parts[-1]] = value


def _get_nested(d: dict[str, Any], path: str) -> Any:
    parts = path.split(".")
    for part in parts:
        if not isinstance(d, dict) or part not in d:
            return None
        d = d[part]
    return d


class OCSFNormalizer(BaseNormalizer):
    """OCSF-based normalizer for network/security events."""

    normalizer_id = "ocsf_normalizer_v1"
    normalizer_name = "OCSF Normalizer v1"
    source_type = ""
    format = ""
    normalizer_version = "1.0.0"
    description = "Maps parsed events to OCSF-aligned common representation"

    field_mappings: dict[str, str] = {}  # noqa: RUF012

    def normalize(self, envelope: EventEnvelope) -> NormalizedEvent:
        if envelope.parsed is None:
            raise ValueError("Envelope has no parsed event")

        parsed = envelope.parsed
        extracted = dict(parsed.extracted)

        ocsf: dict[str, Any] = {}

        # Apply field mappings without mutating extracted
        mapped_extracted = dict(extracted)
        for src_field, dst_path in self.field_mappings.items():
            if src_field in mapped_extracted:
                _set_nested(ocsf, dst_path, mapped_extracted[src_field])

        # Ensure required OCSF structures exist
        ocsf.setdefault("event", {})
        ocsf.setdefault("source", {})
        ocsf.setdefault("destination", {})
        ocsf.setdefault("network", {})
        ocsf.setdefault("device", {})

        # Normalize action
        raw_action = _get_nested(ocsf, "event.action") or extracted.get("action")
        ocsf["event"]["action"] = normalize_action(raw_action)

        # Normalize severity
        raw_severity = _get_nested(ocsf, "event.severity") or extracted.get("severity")
        ocsf["event"]["severity"] = normalize_severity(raw_severity)

        # Normalize timestamp
        raw_time = _get_nested(ocsf, "event.time") or parsed.event_timestamp or envelope.raw.received_at
        ocsf["event"]["time"] = normalize_timestamp(raw_time)

        # Set category/class defaults
        if "category" not in ocsf["event"]:
            ocsf["event"]["category"] = "Network Activity"
        if "class_name" not in ocsf["event"]:
            ocsf["event"]["class_name"] = "Network Activity"

        # Validate and normalize network fields
        src_ip, src_err = validate_ip(ocsf["source"].get("ip") or extracted.get("src_ip") or extracted.get("src"))
        if src_err:
            logger.warning("Source IP validation error for %s: %s", envelope.raw_event_id, src_err)
        ocsf["source"]["ip"] = src_ip

        dst_ip, dst_err = validate_ip(ocsf["destination"].get("ip") or extracted.get("dst_ip") or extracted.get("dst"))
        if dst_err:
            logger.warning("Destination IP validation error for %s: %s", envelope.raw_event_id, dst_err)
        ocsf["destination"]["ip"] = dst_ip

        src_port, src_port_err = validate_port(ocsf["source"].get("port") or extracted.get("src_port"))
        if src_port_err:
            logger.debug("Source port validation note for %s: %s", envelope.raw_event_id, src_port_err)
        ocsf["source"]["port"] = src_port

        dst_port, dst_port_err = validate_port(ocsf["destination"].get("port") or extracted.get("dst_port"))
        if dst_port_err:
            logger.debug("Destination port validation note for %s: %s", envelope.raw_event_id, dst_port_err)
        ocsf["destination"]["port"] = dst_port

        proto, proto_err = validate_protocol(ocsf["network"].get("protocol") or extracted.get("protocol") or extracted.get("proto"))
        if proto_err:
            logger.debug("Protocol validation note for %s: %s", envelope.raw_event_id, proto_err)
        ocsf["network"]["protocol"] = proto

        # Device info
        if "name" not in ocsf["device"]:
            ocsf["device"]["name"] = extracted.get("host") or extracted.get("device_name") or envelope.raw.source_id
        if "type" not in ocsf["device"]:
            ocsf["device"]["type"] = envelope.parsed.source_type if envelope.parsed else "unknown"

        # Build normalized event
        normalized = NormalizedEvent(
            event_id=parsed.event_id,
            raw_event_id=parsed.raw_event_id,
            source_id=parsed.source_id,
            source_type=parsed.source_type,
            format=parsed.format,
            parser_id=parsed.parser_id,
            parser_version=parsed.parser_version,
            schema_version=SCHEMA_VERSION,
            event_timestamp=ocsf["event"].get("time"),
            ingestion_timestamp=envelope.raw.received_at,
            sha256=envelope.sha256,
            ocsf=ocsf,
            parsed_fields=extracted,
            raw_payload=envelope.raw.payload,
        )
        return normalized


class FirewallNormalizer(OCSFNormalizer):
    """Normalizer for Firewall Syslog events."""

    normalizer_id = "firewall_normalizer_v1"
    normalizer_name = "Firewall Normalizer v1"
    source_type = "firewall"
    format = "syslog"
    normalizer_version = "1.0.0"
    description = "Normalizes firewall syslog parsed events"

    field_mappings = {  # noqa: RUF012
        "src_ip": "source.ip",
        "dst_ip": "destination.ip",
        "src_port": "source.port",
        "dst_port": "destination.port",
        "protocol": "network.protocol",
        "action": "event.action",
        "host": "device.name",
        "facility": "device.facility",
        "severity": "event.severity",
    }


class RouterNormalizer(OCSFNormalizer):
    """Normalizer for Router JSON events."""

    normalizer_id = "router_normalizer_v1"
    normalizer_name = "Router Normalizer v1"
    source_type = "router"
    format = "json"
    normalizer_version = "1.0.0"
    description = "Normalizes router JSON parsed events"

    field_mappings = {  # noqa: RUF012
        "src_ip": "source.ip",
        "dst_ip": "destination.ip",
        "src_port": "source.port",
        "dst_port": "destination.port",
        "protocol": "network.protocol",
        "action": "event.action",
        "interface": "device.interface",
        "bytes": "network.bytes",
        "timestamp": "event.time",
    }


class IDSNormalizer(OCSFNormalizer):
    """Normalizer for IDS/IPS CEF events."""

    normalizer_id = "ids_normalizer_v1"
    normalizer_name = "IDS Normalizer v1"
    source_type = "ids"
    format = "cef"
    normalizer_version = "1.0.0"
    description = "Normalizes IDS/IPS CEF parsed events"

    field_mappings = {  # noqa: RUF012
        "src": "source.ip",
        "dst": "destination.ip",
        "act": "event.action",
        "proto": "network.protocol",
        "device_vendor": "device.vendor",
        "device_product": "device.product",
        "device_version": "device.version",
        "signature_id": "event.signature_id",
        "name": "event.name",
        "severity": "event.severity",
        "rt": "event.time",
    }


class NormalizerEngine:
    """Core normalizer engine that consumes parsed events from Kafka and produces
    normalized events or failed events.

    The engine:
    1. Consumes from ``parsed-logs``.
    2. Selects the appropriate normalizer from the registry.
    3. Normalizes the event into a ``NormalizedEvent``.
    4. Publishes to ``normalized-events`` on success or ``failed-events`` on failure.
    """

    def __init__(
        self,
        bootstrap_servers: str | None = None,
        topic_parsed_logs: str | None = None,
        topic_normalized: str | None = None,
        topic_failed: str | None = None,
        group_id: str | None = None,
        lineage_service: LineageService | None = None,
    ) -> None:
        settings = get_settings()
        self.bootstrap_servers = bootstrap_servers or settings.kafka.bootstrap_servers
        self.topic_parsed_logs = topic_parsed_logs or settings.kafka.topic_parsed_logs
        self.topic_normalized = topic_normalized or settings.kafka.topic_normalized
        self.topic_failed = topic_failed or settings.kafka.topic_failed
        self.group_id = group_id or settings.kafka.group_id
        self.lineage_service = lineage_service

        self._normalizers = [
            FirewallNormalizer(),
            RouterNormalizer(),
            IDSNormalizer(),
        ]
        self._producer = UlpfProducer(
            bootstrap_servers=self.bootstrap_servers,
            topic_parsed_logs=self.topic_parsed_logs,
            topic_normalized=self.topic_normalized,
            topic_failed=self.topic_failed,
        )
        self._consumer = UlpfConsumer(
            bootstrap_servers=self.bootstrap_servers,
            topic=self.topic_parsed_logs,
            group_id=self.group_id,
        )
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def _select_normalizer(self, envelope: EventEnvelope) -> BaseNormalizer | None:
        for normalizer in self._normalizers:
            if normalizer.can_handle(envelope):
                return normalizer
        return None

    def _normalize_envelope(self, envelope: EventEnvelope) -> NormalizedEvent | None:
        normalizer = self._select_normalizer(envelope)
        if normalizer is None:
            logger.warning(
                "No normalizer found for raw_event_id=%s source_type=%s format=%s",
                envelope.raw_event_id,
                envelope.parsed.source_type if envelope.parsed else "unknown",
                envelope.parsed.format if envelope.parsed else "unknown",
            )
            return None
        logger.debug(
            "Selected normalizer normalizer_id=%s for raw_event_id=%s",
            normalizer.normalizer_id,
            envelope.raw_event_id,
        )
        return normalizer.normalize(envelope)

    def _publish_normalized(self, envelope: EventEnvelope, normalized: NormalizedEvent) -> None:
        envelope.normalized = normalized
        envelope.processing_status = ProcessingStatus.NORMALIZED.value
        self._producer.publish_normalized(envelope, key=normalized.event_id)
        logger.debug(
            "Queued normalized event raw_event_id=%s normalizer_id=%s",
            envelope.raw_event_id,
            normalizer.normalizer_id if (normalizer := self._select_normalizer(envelope)) else "unknown",
        )
        # Record lineage: parsed_event_id -> normalized_event_id
        if self.lineage_service:
            logger.debug("Recording normalization lineage for raw_event_id=%s", envelope.raw_event_id)
            try:
                import traceback
                self.lineage_service.record_normalization_lineage(envelope)
                logger.info("Recorded normalization lineage: raw=%s -> parsed=%s -> normalized=%s",
                           envelope.raw.raw_event_id,
                           envelope.parsed.event_id if envelope.parsed else "unknown",
                           envelope.normalized.event_id if envelope.normalized else "unknown")
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to record normalization lineage: raw_event_id=%s error=%s\n%s",
                              envelope.raw_event_id, exc, traceback.format_exc())

    def _publish_failed(self, envelope: EventEnvelope, error: EventError) -> None:
        envelope.processing_status = ProcessingStatus.FAILED.value
        envelope.error = error
        failed_envelope = EventEnvelope(
            raw=envelope.raw,
            parsed=envelope.parsed,
            normalized=envelope.normalized,
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
            "Published failed normalized event raw_event_id=%s error=%s",
            envelope.raw_event_id,
            error.message,
        )

    def _handle_envelope(self, envelope: EventEnvelope) -> None:
        try:
            normalized = self._normalize_envelope(envelope)
        except Exception as exc:  # noqa: BLE001
            error = EventError.from_exception("normalizer", "E_NORM_001", exc)
            self._publish_failed(envelope, error)
            return

        if normalized is None:
            error = EventError(
                stage="normalizer",
                code="E_NO_NORMALIZER",
                message=f"No normalizer available for source_type={envelope.parsed.source_type if envelope.parsed else 'unknown'} format={envelope.parsed.format if envelope.parsed else 'unknown'}",
            )
            self._publish_failed(envelope, error)
            return

        try:
            self._publish_normalized(envelope, normalized)
        except Exception as exc:  # noqa: BLE001
            error = EventError.from_exception("publisher", "E_PUBLISH_001", exc)
            self._publish_failed(envelope, error)

    def start(self, poll_timeout: float = 1.0) -> None:
        """Start the normalizer engine in a background daemon thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            args=(poll_timeout,),
            daemon=True,
        )
        self._thread.start()
        logger.info("Normalizer engine started group=%s topic=%s", self.group_id, self.topic_parsed_logs)

    def _run(self, poll_timeout: float) -> None:
        self._consumer.consume(self._handle_envelope, poll_timeout=poll_timeout)

    def stop(self) -> None:
        """Stop the normalizer engine and release resources."""
        self._stop_event.set()
        self._consumer.stop()
        self._producer.close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        logger.info("Normalizer engine stopped")
