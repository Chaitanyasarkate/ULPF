"""
Core data model for ULPF.

Every event flowing through the ULPF pipeline is wrapped in a canonical
``EventEnvelope`` that carries strong provenance from ingestion through
normalization, storage, and downstream consumption.

This model is the single source of truth for the fields required by the
problem statement (PS ID: 26156), including raw-to-normalized traceability,
SHA-256 integrity, and hash-chain linkage.

Design principles:
  * The original/raw payload is NEVER overwritten or discarded.
  * ``raw_event_id`` always traces back to the exact original event.
  * Normalization is additive — unknown fields are preserved, never dropped.
  * A ``processing_status`` and optional ``error`` capture pipeline failures
    so no event is silently lost.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ProcessingStatus(str, enum.Enum):
    """Lifecycle status of an event within the pipeline."""

    RECEIVED = "received"
    RAW_STORED = "raw_stored"
    PARSED = "parsed"
    NORMALIZED = "normalized"
    VALIDATED = "validated"
    STORED = "stored"
    ENRICHED = "enriched"
    FAILED = "failed"
    DLQ = "dead_letter"
    SCHEMA_DRIFT = "schema_drift"

    def __str__(self) -> str:
        return self.value


class SourceType(str, enum.Enum):
    """Logical classification of a log source."""

    FIREWALL = "firewall"
    ROUTER = "router"
    IDS = "ids"
    IPS = "ips"
    VPN = "vpn"
    SWITCH = "switch"
    SERVER = "server"
    APPLICATION = "application"
    CUSTOM = "custom"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value


# A small, fixed schema version namespace so downstream consumers and the
# lineage layer can reason about structural changes to normalized events.
SCHEMA_VERSION = "1.0.0"


@dataclass
class EventError:
    """Captures an error encountered while processing an event."""

    stage: str
    code: str
    message: str
    traceback: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "code": self.code,
            "message": self.message,
            "traceback": self.traceback,
        }

    @classmethod
    def from_exception(cls, stage: str, code: str, exc: BaseException) -> EventError:
        import traceback as _tb

        return cls(
            stage=stage,
            code=code,
            message=str(exc),
            traceback="".join(_tb.format_exception(type(exc), exc, exc.__traceback__)),
        )


@dataclass
class RawEvent:
    """The immutable, lossless original payload of a single log event.

    A ``RawEvent`` is assigned two identifiers:
      * ``raw_event_id`` — a stable identity for the *exact* original payload.
      * ``event_id``     — a fresh identity generated when the payload first
        enters the pipeline (one payload may produce one event_id).

    Storing the payload as-is guarantees lossless preservation.
    """

    raw_event_id: str = field(default_factory=lambda: str(uuid4()))
    source_id: str = ""
    source_type: str = ""
    format: str = ""
    received_at: str = field(default_factory=_utcnow_iso)
    payload: str = ""
    original_payload_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_event_id": self.raw_event_id,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "format": self.format,
            "received_at": self.received_at,
            "payload": self.payload,
            "original_payload_bytes": self.original_payload_bytes,
        }


@dataclass
class ParsedEvent:
    """Structured fields extracted by a parser, without normalization.

    ``extracted`` must contain every field the parser was able to resolve.
    Fields that cannot be extracted are simply absent (never silently dropped
    from the raw side — they remain in ``RawEvent.payload``).
    """

    event_id: str = field(default_factory=lambda: str(uuid4()))
    raw_event_id: str = ""
    source_id: str = ""
    source_type: str = ""
    format: str = ""
    parser_id: str = ""
    parser_version: str = ""
    extracted: dict[str, Any] = field(default_factory=dict)
    event_timestamp: str | None = None
    parsed_at: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "raw_event_id": self.raw_event_id,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "format": self.format,
            "parser_id": self.parser_id,
            "parser_version": self.parser_version,
            "extracted": dict(self.extracted),
            "event_timestamp": self.event_timestamp,
            "parsed_at": self.parsed_at,
        }


@dataclass
class NormalizedEvent:
    """OCSF-based common event representation.

    The normalized event maps source-specific fields onto a common schema.
    The complete set of extracted fields is ALSO preserved under
    ``parsed_fields`` so normalization never loses information.
    """

    event_id: str = ""
    raw_event_id: str = ""
    source_id: str = ""
    source_type: str = ""
    format: str = ""
    parser_id: str = ""
    parser_version: str = ""
    schema_version: str = SCHEMA_VERSION
    event_timestamp: str | None = None
    ingestion_timestamp: str = field(default_factory=_utcnow_iso)
    sha256: str = ""
    # OCSF-aligned normalized fields (category, type, src/dst, action, etc.)
    ocsf: dict[str, Any] = field(default_factory=dict)
    # Full original extracted fields, retained verbatim (information-preservation).
    parsed_fields: dict[str, Any] = field(default_factory=dict)
    raw_payload: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "raw_event_id": self.raw_event_id,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "format": self.format,
            "parser_id": self.parser_id,
            "parser_version": self.parser_version,
            "schema_version": self.schema_version,
            "event_timestamp": self.event_timestamp,
            "ingestion_timestamp": self.ingestion_timestamp,
            "sha256": self.sha256,
            "ocsf": dict(self.ocsf),
            "parsed_fields": dict(self.parsed_fields),
            "raw_payload": self.raw_payload,
        }


@dataclass
class EventEnvelope:
    """
    The single message that travels between ULPF pipeline stages and is
    produced/consumed on Kafka topics.

    An envelope always carries the original payload and is never mutated in a
    way that loses information. Failed stages record an ``EventError`` and a
    ``processing_status`` without discarding the event.
    """

    raw: RawEvent = field(default_factory=RawEvent)
    parsed: ParsedEvent | None = None
    normalized: NormalizedEvent | None = None
    # Integrity: SHA-256 of the current raw payload (set during raw storage).
    sha256: str = ""
    # Hash-chain linkage: previous raw payload hash / current hash.
    previous_hash: str = ""
    current_hash: str = ""
    # Provenance / pipeline state.
    processing_status: str = ProcessingStatus.RECEIVED.value
    error: EventError | None = None
    # The parser config (id+version) selected for this event, if any.
    parser_id: str = ""
    parser_version: str = ""
    schema_version: str = SCHEMA_VERSION
    # Metadata for the schema-drift detector.
    drift_flags: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(
        cls,
        payload: str,
        source_id: str = "",
        source_type: str = "",
        fmt: str = "",
    ) -> EventEnvelope:
        """Create an envelope from an incoming raw log line."""
        raw = RawEvent(
            source_id=source_id,
            source_type=source_type,
            format=fmt,
            payload=payload,
            original_payload_bytes=len(payload.encode("utf-8")),
        )
        return cls(raw=raw, processing_status=ProcessingStatus.RECEIVED.value)

    @property
    def event_id(self) -> str:
        if self.parsed is not None:
            return self.parsed.event_id
        return ""

    @property
    def raw_event_id(self) -> str:
        return self.raw.raw_event_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw.to_dict(),
            "parsed": self.parsed.to_dict() if self.parsed else None,
            "normalized": self.normalized.to_dict() if self.normalized else None,
            "sha256": self.sha256,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
            "processing_status": self.processing_status,
            "error": self.error.to_dict() if self.error else None,
            "parser_id": self.parser_id,
            "parser_version": self.parser_version,
            "schema_version": self.schema_version,
            "drift_flags": dict(self.drift_flags),
        }

    def to_kafka_value(self) -> bytes:
        import json

        return json.dumps(self.to_dict(), sort_keys=False).encode("utf-8")

    @classmethod
    def from_kafka_value(cls, data: bytes) -> EventEnvelope:
        import json

        payload = json.loads(data.decode("utf-8"))

        raw = RawEvent(
            raw_event_id=payload["raw"]["raw_event_id"],
            source_id=payload["raw"]["source_id"],
            source_type=payload["raw"]["source_type"],
            format=payload["raw"]["format"],
            received_at=payload["raw"]["received_at"],
            payload=payload["raw"]["payload"],
            original_payload_bytes=payload["raw"]["original_payload_bytes"],
        )

        parsed = None
        if payload.get("parsed"):
            parsed = ParsedEvent(
                event_id=payload["parsed"]["event_id"],
                raw_event_id=payload["parsed"]["raw_event_id"],
                source_id=payload["parsed"]["source_id"],
                source_type=payload["parsed"]["source_type"],
                format=payload["parsed"]["format"],
                parser_id=payload["parsed"]["parser_id"],
                parser_version=payload["parsed"]["parser_version"],
                extracted=payload["parsed"]["extracted"],
                event_timestamp=payload["parsed"].get("event_timestamp"),
                parsed_at=payload["parsed"]["parsed_at"],
            )

        normalized = None
        if payload.get("normalized"):
            normalized = NormalizedEvent(
                event_id=payload["normalized"]["event_id"],
                raw_event_id=payload["normalized"]["raw_event_id"],
                source_id=payload["normalized"]["source_id"],
                source_type=payload["normalized"]["source_type"],
                format=payload["normalized"]["format"],
                parser_id=payload["normalized"]["parser_id"],
                parser_version=payload["normalized"]["parser_version"],
                schema_version=payload["normalized"]["schema_version"],
                event_timestamp=payload["normalized"].get("event_timestamp"),
                ingestion_timestamp=payload["normalized"]["ingestion_timestamp"],
                sha256=payload["normalized"].get("sha256", ""),
                ocsf=payload["normalized"]["ocsf"],
                parsed_fields=payload["normalized"]["parsed_fields"],
                raw_payload=payload["normalized"]["raw_payload"],
            )

        error = None
        if payload.get("error"):
            error = EventError(
                stage=payload["error"]["stage"],
                code=payload["error"]["code"],
                message=payload["error"]["message"],
                traceback=payload["error"].get("traceback"),
            )

        return cls(
            raw=raw,
            parsed=parsed,
            normalized=normalized,
            sha256=payload.get("sha256", ""),
            previous_hash=payload.get("previous_hash", ""),
            current_hash=payload.get("current_hash", ""),
            processing_status=payload.get("processing_status", ProcessingStatus.RECEIVED.value),
            error=error,
            parser_id=payload.get("parser_id", ""),
            parser_version=payload.get("parser_version", ""),
            schema_version=payload.get("schema_version", SCHEMA_VERSION),
            drift_flags=payload.get("drift_flags", {}),
        )


def generate_event_id() -> str:
    """Generate a new unique event identifier (UUID4)."""
    return str(uuid4())


def parse_uuid(value: str) -> UUID:
    """Parse a UUID string, raising ValueError on invalid input."""
    return UUID(value)
