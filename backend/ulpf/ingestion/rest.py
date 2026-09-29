"""REST API ingestion endpoint for ULPF Phase 2."""

from __future__ import annotations

import logging
from typing import Any

from flask import Flask, jsonify, request

from ulpf.config import get_settings
from ulpf.ingestion.base import ingest_raw
from ulpf.ingestion.kafka_publisher import KafkaPublisher
from ulpf.ingestion.metrics import IngestionMetrics
from ulpf.ingestion.sink import RawEventSink

logger = logging.getLogger("ulpf.ingestion.rest")

app = Flask(__name__)
settings = get_settings()

# Default shared sink, metrics, and Kafka publisher for the REST service.
_metrics = IngestionMetrics()
_sink = RawEventSink(metrics=_metrics)
_kafka_publisher = KafkaPublisher()


@app.get("/health")
def health() -> Any:
    return jsonify({"status": "ok"}), 200


@app.post("/api/v1/ingest")
def ingest() -> Any:
    try:
        body = request.get_json(force=False, silent=True)
    except Exception:  # noqa: BLE001
        logger.warning("Malformed JSON in ingest request")
        _metrics.record_failure()
        return jsonify({"error": "malformed_json", "message": "Request body is not valid JSON."}), 400

    if not isinstance(body, dict):
        logger.warning("Ingest request body is not a JSON object")
        _metrics.record_failure()
        return jsonify({"error": "invalid_body", "message": "Request body must be a JSON object."}), 400

    payload = body.get("payload")
    if not isinstance(payload, str) or not payload.strip():
        logger.warning("Ingest request missing or empty 'payload'")
        _metrics.record_failure()
        return jsonify({"error": "missing_payload", "message": "Field 'payload' must be a non-empty string."}), 400

    source_id = body.get("source_id", "")
    source_type = body.get("source_type", "")
    fmt = body.get("format", "")

    try:
        envelope = ingest_raw(
            payload=payload,
            source_id=str(source_id),
            source_type=str(source_type),
            fmt=str(fmt),
            sink=_sink,
            method="rest",
        )
    except Exception:
        logger.exception("Failed to process ingest request")
        _metrics.record_failure()
        return jsonify({"error": "processing_error", "message": "Internal processing error."}), 500

    try:
        published = _kafka_publisher.publish(envelope)
    except Exception:
        logger.exception("Kafka publisher error")
        published = False

    if not published:
        _metrics.record_failure()
        return jsonify({"error": "kafka_error", "message": "Failed to publish event to Kafka."}), 500

    _sink.mark_success(envelope)

    return jsonify({
        "status": "accepted",
        "raw_event_id": envelope.raw_event_id,
        "event_id": envelope.event_id,
        "processing_status": envelope.processing_status,
        "sha256": envelope.sha256,
    }), 202


@app.get("/metrics")
def metrics() -> Any:
    snap = _metrics.snapshot()
    if _kafka_publisher.producer is not None:
        snap["kafka"] = _kafka_publisher.producer.metrics()
    return jsonify(snap), 200


def create_app(
    sink: RawEventSink | None = None,
    metrics: IngestionMetrics | None = None,
    kafka_publisher: KafkaPublisher | None = None,
) -> Flask:
    """Create and configure the Flask ingestion app.

    Args:
        sink: Optional shared raw-event sink. Falls back to the module default.
        metrics: Optional shared metrics collector. Falls back to the module default.
        kafka_publisher: Optional shared Kafka publisher. Falls back to module default.
    """
    global _sink, _metrics, _kafka_publisher
    if sink is not None:
        _sink = sink
    if metrics is not None:
        _metrics = metrics
    if kafka_publisher is not None:
        _kafka_publisher = kafka_publisher
    return app
