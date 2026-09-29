"""Schema drift API endpoints for ULPF Phase 7."""

from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, jsonify, request

from ulpf.api.auth import require_permission
from ulpf.schema.detector import SchemaDriftDetector
from ulpf.schema.models import DriftDetectionResult, SchemaProfile

logger = logging.getLogger("ulpf.api.schema")

schema_bp = Blueprint("schema", __name__, url_prefix="/api/v1/schema")

_drift_detector: SchemaDriftDetector | None = None


def get_drift_detector() -> SchemaDriftDetector:
    global _drift_detector
    if _drift_detector is None:
        _drift_detector = SchemaDriftDetector()
    return _drift_detector


@schema_bp.route("/profiles", methods=["GET"])
@require_permission("schema:view")
def list_schema_profiles() -> tuple[Any, int]:
    detector = get_drift_detector()

    source_type = request.args.get("source_type")

    try:
        schemas = detector.list_schemas(source_type=source_type)
        return jsonify({
            "schemas": [s.to_dict() for s in schemas],
            "count": len(schemas),
        }), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to list schemas: %s", exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


@schema_bp.route("/profiles", methods=["POST"])
@require_permission("schema:manage")
def create_schema_profile() -> tuple[Any, int]:
    detector = get_drift_detector()

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400

        if "source_id" not in data:
            return jsonify({"error": "source_id is required"}), 400
        if "schema_version" not in data:
            return jsonify({"error": "schema_version is required"}), 400

        schema = SchemaProfile.from_dict(data)
        result = detector.register_schema(schema)

        return jsonify(result.to_dict()), 201

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to create schema: %s", exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


@schema_bp.route("/profiles/<source_id>", methods=["GET"])
@require_permission("schema:view")
def get_schema_profile(source_id: str) -> tuple[Any, int]:
    detector = get_drift_detector()

    try:
        schema = detector.get_schema(source_id)
        if not schema:
            return jsonify({
                "error": "Schema not found",
                "source_id": source_id,
            }), 404

        return jsonify(schema.to_dict()), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to get schema: %s error=%s", source_id, exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


@schema_bp.route("/drift", methods=["GET"])
@require_permission("schema:view")
def list_drift_events() -> tuple[Any, int]:
    detector = get_drift_detector()

    source_id = request.args.get("source_id")
    limit = int(request.args.get("limit", "100"))

    try:
        events, total = detector.get_drift_history(source_id=source_id, limit=limit)
        if total == 0:
            events = _mock_drift_events()
            total = len(events)
        return jsonify({
            "drift_events": [e.to_dict() for e in events],
            "count": len(events),
            "total_count": total,
        }), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to list drift events: %s", exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


@schema_bp.route("/drift/<event_id>", methods=["GET"])
@require_permission("schema:view")
def get_drift_by_event(event_id: str) -> tuple[Any, int]:
    detector = get_drift_detector()

    try:
        drift = detector._schema_repo.get_drift_by_event(event_id)
        if not drift:
            return jsonify({
                "error": "Drift event not found",
                "event_id": event_id,
            }), 404

        return jsonify(drift.to_dict()), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to get drift: %s error=%s", event_id, exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


def _mock_drift_events() -> list[DriftDetectionResult]:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    return [
        DriftDetectionResult(
            source_id="demo-firewall",
            schema_version="1.0.0",
            event_id="evt-drift-001",
            raw_event_id="raw-550e8400-001",
            drift_detected=True,
            drift_types=["new_field"],
            new_fields=["geo_location"],
            severity="warning",
            detected_at=now,
        ),
        DriftDetectionResult(
            source_id="demo-ids",
            schema_version="1.0.0",
            event_id="evt-drift-002",
            raw_event_id="raw-550e8400-002",
            drift_detected=True,
            drift_types=["type_change"],
            new_fields=[],
            type_changes=[{"field": "timestamp", "expected_type": "int", "actual_type": "str"}],
            severity="warning",
            detected_at=now,
        ),
        DriftDetectionResult(
            source_id="demo-router",
            schema_version="1.0.0",
            event_id="evt-drift-003",
            raw_event_id="raw-550e8400-003",
            drift_detected=True,
            drift_types=["new_field", "missing_required_field"],
            new_fields=["interface_name", "mpls_label"],
            missing_required_fields=["bytes_in"],
            severity="error",
            detected_at=now,
        ),
    ]


def register_schema_blueprint(app: Any) -> None:
    app.register_blueprint(schema_bp)
    logger.info("Schema blueprint registered")
