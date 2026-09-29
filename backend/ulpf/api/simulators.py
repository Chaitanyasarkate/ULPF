"""Simulator control API endpoints for ULPF.

Allows the dashboard to start/stop log source simulators
(firewall, router, ids) via REST.
"""

from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, jsonify

from ulpf.api.auth import require_permission
from ulpf.simulators.manager import get_simulator_manager

logger = logging.getLogger("ulpf.api.simulators")

simulators_bp = Blueprint("simulators", __name__, url_prefix="/api/v1/simulators")


@simulators_bp.route("", methods=["GET"])
@require_permission("simulators:view")
def list_simulators() -> tuple[Any, int]:
    """Return status of all simulators."""
    manager = get_simulator_manager()
    return jsonify(manager.status()), 200


@simulators_bp.route("/start", methods=["POST"])
@require_permission("simulators:manage")
def start_simulators() -> tuple[Any, int]:
    """Start all simulators."""
    manager = get_simulator_manager()
    result = manager.start_all()
    return jsonify(result), 200


@simulators_bp.route("/stop", methods=["POST"])
@require_permission("simulators:manage")
def stop_simulators() -> tuple[Any, int]:
    """Stop all simulators."""
    manager = get_simulator_manager()
    result = manager.stop_all()
    return jsonify(result), 200


@simulators_bp.route("/<name>/start", methods=["POST"])
@require_permission("simulators:manage")
def start_simulator(name: str) -> tuple[Any, int]:
    """Start a single simulator by name."""
    manager = get_simulator_manager()
    result = manager.start(name)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result), 200


@simulators_bp.route("/<name>/stop", methods=["POST"])
@require_permission("simulators:manage")
def stop_simulator(name: str) -> tuple[Any, int]:
    """Stop a single simulator by name."""
    manager = get_simulator_manager()
    result = manager.stop(name)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result), 200


def register_simulators_blueprint(app: Any) -> None:
    app.register_blueprint(simulators_bp)
    logger.info("Simulators blueprint registered")