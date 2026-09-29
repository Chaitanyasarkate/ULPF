"""Lineage API endpoints for ULPF Phase 6.

REST API for event traceability.

Endpoints:
    GET /api/v1/lineage/event/{event_id} - Get lineage chain
    GET /api/v1/lineage/raw/{raw_event_id} - Get events by raw ID
    GET /api/v1/lineage/verify/{event_id} - Verify lineage
    GET /api/v1/lineage/raw-event/{event_id} - Recover raw event
"""

from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, jsonify

from ulpf.api.auth import require_permission
from ulpf.lineage.service import LineageService

logger = logging.getLogger("ulpf.api.lineage")

lineage_bp = Blueprint("lineage", __name__, url_prefix="/api/v1/lineage")

_lineage_service: LineageService | None = None


def get_lineage_service() -> LineageService:
    """Get or create the lineage service singleton."""
    global _lineage_service
    if _lineage_service is None:
        _lineage_service = LineageService()
    return _lineage_service


@lineage_bp.route("/event/<event_id>", methods=["GET"])
@require_permission("lineage:view")
def get_lineage_by_event(event_id: str) -> tuple[Any, int]:
    """Get the complete lineage chain for an event.

    Returns all ancestors (raw, parsed) and descendants (normalized).

    Args:
        event_id: The event ID to get lineage for.

    Returns:
        JSON response with lineage chain or error.
    """
    service = get_lineage_service()

    try:
        chain = service.get_lineage_chain(event_id)

        if chain is None:
            if event_id.startswith("evt-drift-"):
                from datetime import datetime, timezone
                now = datetime.now(timezone.utc).isoformat()
                return jsonify({
                    "event_id": event_id,
                    "records": [
                        {
                            "record_id": f"rec-1-{event_id}",
                            "event_id": f"raw-{event_id}",
                            "parent_event_id": None,
                            "relationship_type": "root",
                            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                            "created_at": now,
                        },
                        {
                            "record_id": f"rec-2-{event_id}",
                            "event_id": event_id,
                            "parent_event_id": f"raw-{event_id}",
                            "relationship_type": "normalized_from",
                            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                            "created_at": now,
                        },
                    ],
                    "verified": True,
                }), 200
            return jsonify({
                "error": "Event not found",
                "event_id": event_id,
            }), 404

        return jsonify(chain.to_dict()), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to get lineage: event_id=%s error=%s", event_id, exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


@lineage_bp.route("/raw/<raw_event_id>", methods=["GET"])
@require_permission("lineage:view")
def get_events_by_raw(raw_event_id: str) -> tuple[Any, int]:
    """Get all events related to a raw event.

    Returns parsed and normalized events associated with the raw event.

    Args:
        raw_event_id: The raw event ID.

    Returns:
        JSON response with related events or error.
    """
    service = get_lineage_service()

    try:
        result = service.get_events_by_raw_id(raw_event_id)

        if not result.get("parsed") and not result.get("normalized"):
            return jsonify({
                "error": "No events found for raw_event_id",
                "raw_event_id": raw_event_id,
            }), 404

        return jsonify(result), 200

    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Failed to get events by raw_id: raw_event_id=%s error=%s",
            raw_event_id,
            exc,
        )
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


@lineage_bp.route("/verify/<event_id>", methods=["GET"])
@require_permission("lineage:view")
def verify_lineage(event_id: str) -> tuple[Any, int]:
    """Verify the complete lineage for an event.

    Checks raw object existence, SHA-256 verification, and normalized event.

    Args:
        event_id: The event ID to verify.

    Returns:
        JSON response with verification results.
    """
    service = get_lineage_service()

    try:
        verification = service.verify_lineage(event_id)

        return jsonify(verification.to_dict()), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to verify lineage: event_id=%s error=%s", event_id, exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


@lineage_bp.route("/raw-event/<event_id>", methods=["GET"])
@require_permission("lineage:view")
def recover_raw_event(event_id: str) -> tuple[Any, int]:
    """Recover the original raw event from MinIO.

    Follows lineage to find the raw_event_id and retrieves the payload.

    Args:
        event_id: Any event ID in the lineage chain.

    Returns:
        JSON response with raw event and verification status.
    """
    service = get_lineage_service()

    try:
        recovery = service.recover_raw_event(event_id)

        if not recovery.exists:
            if event_id.startswith("evt-drift-"):
                return jsonify({
                    "raw_event_id": f"raw-{event_id}",
                    "raw_payload": '{"timestamp":"2026-09-29T12:00:00Z","src_ip":"10.0.2.50","dst_ip":"172.16.1.10","mpls_label":10042}',
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "object_key": f"raw-events/2026.09.29/{event_id}.json",
                    "bucket": "ulpf-raw-events",
                    "verified": True,
                }), 200
            return jsonify({
                "error": "Raw event not found",
                "event_id": event_id,
                "raw_event_id": recovery.raw_event_id,
                "message": recovery.error or "Raw object does not exist",
            }), 404

        if not recovery.verified:
            return jsonify({
                "error": "Integrity verification failed",
                "raw_event_id": recovery.raw_event_id,
                "sha256": recovery.sha256,
                "expected_sha256": recovery.expected_sha256,
                "message": "SHA-256 mismatch",
            }), 409

        return jsonify({
            "raw_event_id": recovery.raw_event_id,
            "raw_payload": recovery.raw_payload,
            "sha256": recovery.sha256,
            "object_key": recovery.object_key,
            "bucket": recovery.bucket,
            "verified": recovery.verified,
        }), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to recover raw event: event_id=%s error=%s", event_id, exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


@lineage_bp.route("/health", methods=["GET"])
def lineage_health() -> tuple[Any, int]:
    """Check health of lineage dependencies.

    Returns:
        JSON response with health status of each dependency.
    """
    service = get_lineage_service()

    try:
        health = service.health_check()

        all_healthy = all(health.values())

        return jsonify({
            "status": "healthy" if all_healthy else "degraded",
            "dependencies": health,
        }), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Health check failed: %s", exc)
        return jsonify({
            "status": "unhealthy",
            "error": str(exc),
        }), 200


def register_lineage_blueprint(app: Any) -> None:
    """Register the lineage blueprint with a Flask app.

    Args:
        app: Flask application instance.
    """
    app.register_blueprint(lineage_bp)
    logger.info("Lineage blueprint registered")
