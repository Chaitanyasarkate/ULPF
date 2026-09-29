"""Wire /api/v1/anomalies to the real AnomalyRepository.

Replaces the synchronous stub with a real query over stored anomalies.
Uses the same JWT bearer auth pattern as every other working endpoint.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from flask import Blueprint, jsonify, request

from ulpf.api.auth import require_permission
from ulpf.analytics.repository import AnomalyRepository
from ulpf.analytics.models import AnomalySeverity, AnomalyStatus

logger = logging.getLogger("ulpf.api.anomalies")

anomalies_bp = Blueprint("anomalies", __name__, url_prefix="/api/v1/anomalies")


def _run_async(coro):
    """Run an async coroutine from sync Flask code.

    Uses a persistent event loop in a dedicated daemon thread so that
    asyncpg connection pools survive across multiple HTTP requests.
    """
    import threading

    if not hasattr(_run_async, "_loop") or _run_async._loop is None:
        _run_async._loop = asyncio.new_event_loop()
        _run_async._thread = threading.Thread(
            target=_run_async._loop.run_forever, daemon=True
        )
        _run_async._thread.start()

    future = asyncio.run_coroutine_threadsafe(coro, _run_async._loop)
    return future.result()


@anomalies_bp.route("/health-simple", methods=["GET"])
def anomalies_health_simple() -> tuple[Any, int]:
    """Simple health check without auth."""
    return jsonify({"status": "healthy", "service": "anomalies", "mode": "sync"}), 200


@anomalies_bp.route("/health", methods=["GET"])
@require_permission("health:view")
def anomalies_health() -> tuple[Any, int]:
    """Health check for anomaly detection service."""
    return jsonify({"status": "healthy", "service": "anomalies", "mode": "sync"}), 200


@anomalies_bp.route("", methods=["GET"])
@require_permission("analytics:view")
def list_anomalies() -> tuple[Any, int]:
    """List anomalies with filtering and pagination.

    Query params:
        source_id: filter by source
        rule_id: filter by rule
        severity: filter by severity (low/medium/high/critical)
        status: filter by status (open/acknowledged/closed)
        page: page number (default 1)
        page_size: page size (default 50)
    """
    try:
        source_id = request.args.get("source_id")
        rule_id = request.args.get("rule_id")
        severity_str = request.args.get("severity")
        status_str = request.args.get("status")
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", 50))

        severity = AnomalySeverity(severity_str) if severity_str else None
        status = AnomalyStatus(status_str) if status_str else None

        repo = AnomalyRepository()
        try:
            anomalies, total = _run_async(repo.list_anomalies(
                source_id=source_id,
                rule_id=rule_id,
                severity=severity,
                status=status,
                page=page,
                page_size=page_size,
            ))
        finally:
            _run_async(repo.close())

        return jsonify({
            "anomalies": [a.to_dict() for a in anomalies],
            "total": total,
            "page": page,
            "page_size": page_size,
        }), 200

    except Exception as exc:
        logger.warning("Anomaly list failed: %s", exc)
        return jsonify({
            "anomalies": [],
            "total": 0,
            "page": 1,
            "page_size": 50,
            "error": str(exc),
        }), 200


@anomalies_bp.route("/rules", methods=["GET"])
@require_permission("analytics:view")
def list_rules() -> tuple[Any, int]:
    """List all anomaly detection rules."""
    try:
        repo = AnomalyRepository()
        try:
            rules = _run_async(repo.get_rules())
        finally:
            _run_async(repo.close())

        return jsonify({
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "rule_name": r.rule_name,
                    "rule_type": r.rule_type.value,
                    "description": r.description,
                    "enabled": r.enabled,
                    "thresholds": r.thresholds,
                    "cooldown_seconds": r.cooldown_seconds,
                }
                for r in rules
            ],
            "count": len(rules),
        }), 200

    except Exception as exc:
        logger.warning("Rules list failed: %s", exc)
        return jsonify({"rules": [], "count": 0, "error": str(exc)}), 200


def register_anomalies_blueprint(app: Any) -> None:
    """Register the anomalies blueprint with the Flask app."""
    app.register_blueprint(anomalies_bp)
    logger.info("Anomalies blueprint registered at /api/v1/anomalies (sync)")