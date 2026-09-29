"""Base ingestion helpers shared across ingestion methods."""

from __future__ import annotations

from ulpf.common.hashing import sha256_str
from ulpf.common.models import EventEnvelope, ParsedEvent, ProcessingStatus


def ingest_raw(
    payload: str,
    source_id: str = "",
    source_type: str = "",
    fmt: str = "",
    sink=None,
    method: str = "unknown",
) -> EventEnvelope:
    """Create an EventEnvelope from a raw payload and store it in the sink.

    Args:
        payload: The original raw log payload.
        source_id: Identifier of the source device/system.
        source_type: Logical source type (firewall, router, ids, ...).
        fmt: Format of the payload (syslog, json, cef, ...).
        sink: Optional RawEventSink to store the envelope.
        method: Ingestion method label for metrics.

    Returns:
        The created EventEnvelope.
    """
    envelope = EventEnvelope.from_raw(
        payload=payload,
        source_id=source_id,
        source_type=source_type,
        fmt=fmt,
    )
    envelope.sha256 = sha256_str(payload)
    envelope.processing_status = ProcessingStatus.RECEIVED.value
    envelope.parsed = ParsedEvent(
        raw_event_id=envelope.raw_event_id,
        source_id=source_id,
        source_type=source_type,
        format=fmt,
    )

    if sink is not None:
        sink.store(envelope, method=method)

    return envelope
