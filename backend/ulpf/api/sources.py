"""Source management API endpoints for ULPF Phase 7."""

from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, jsonify, request

from ulpf.api.auth import require_permission
from ulpf.onboarding.manager import SourceOnboardingManager, ValidationError
from ulpf.onboarding.models import SourceProfile

logger = logging.getLogger("ulpf.api.sources")

sources_bp = Blueprint("sources", __name__, url_prefix="/api/v1/sources")

_onboarding_manager: SourceOnboardingManager | None = None


def get_onboarding_manager() -> SourceOnboardingManager:
    global _onboarding_manager
    if _onboarding_manager is None:
        _onboarding_manager = SourceOnboardingManager()
    return _onboarding_manager


@sources_bp.route("", methods=["GET"])
@require_permission("sources:view")
def list_sources() -> tuple[Any, int]:
    print("=== list_sources called ===", flush=True)
    manager = get_onboarding_manager()

    source_type = request.args.get("source_type")
    enabled_only = request.args.get("enabled_only", "false").lower() == "true"

    try:
        sources = manager.list_sources(
            source_type=source_type,
            enabled_only=enabled_only,
        )
        return jsonify({
            "sources": [s.to_dict() for s in sources],
            "count": len(sources),
        }), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to list sources: %s", exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


@sources_bp.route("", methods=["POST"])
@require_permission("sources:manage")
def create_source() -> tuple[Any, int]:
    manager = get_onboarding_manager()

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400

        profile = SourceProfile.from_dict(data)
        result = manager.register(profile)

        return jsonify(result.to_dict()), 201

    except ValidationError as ve:
        return jsonify({
            "error": "Validation failed",
            "details": ve.errors,
        }), 400

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to create source: %s", exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


@sources_bp.route("/<source_id>", methods=["GET"])
@require_permission("sources:view")
def get_source(source_id: str) -> tuple[Any, int]:
    manager = get_onboarding_manager()

    try:
        profile = manager.get(source_id)
        if not profile:
            return jsonify({
                "error": "Source not found",
                "source_id": source_id,
            }), 404

        return jsonify(profile.to_dict()), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to get source: %s error=%s", source_id, exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


@sources_bp.route("/<source_id>", methods=["PUT"])
@require_permission("sources:manage")
def update_source(source_id: str) -> tuple[Any, int]:
    manager = get_onboarding_manager()

    try:
        existing = manager.get(source_id)
        if not existing:
            return jsonify({
                "error": "Source not found",
                "source_id": source_id,
            }), 404

        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400

        profile = SourceProfile.from_dict({**existing.to_dict(), **data})
        profile.source_id = source_id
        result = manager.register(profile)

        return jsonify(result.to_dict()), 200

    except ValidationError as ve:
        return jsonify({
            "error": "Validation failed",
            "details": ve.errors,
        }), 400

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to update source: %s error=%s", source_id, exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


@sources_bp.route("/<source_id>", methods=["DELETE"])
@require_permission("sources:manage")
def delete_source(source_id: str) -> tuple[Any, int]:
    manager = get_onboarding_manager()

    try:
        success = manager.unregister(source_id)
        if not success:
            return jsonify({
                "error": "Source not found or could not be deleted",
                "source_id": source_id,
            }), 404

        return jsonify({
            "message": "Source deleted",
            "source_id": source_id,
        }), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to delete source: %s error=%s", source_id, exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


@sources_bp.route("/<source_id>/enable", methods=["POST"])
@require_permission("sources:manage")
def enable_source(source_id: str) -> tuple[Any, int]:
    manager = get_onboarding_manager()

    try:
        result = manager.enable(source_id)
        if not result:
            return jsonify({
                "error": "Source not found",
                "source_id": source_id,
            }), 404

        return jsonify(result.to_dict()), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to enable source: %s error=%s", source_id, exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


@sources_bp.route("/<source_id>/disable", methods=["POST"])
@require_permission("sources:manage")
def disable_source(source_id: str) -> tuple[Any, int]:
    manager = get_onboarding_manager()

    try:
        result = manager.disable(source_id)
        if not result:
            return jsonify({
                "error": "Source not found",
                "source_id": source_id,
            }), 404

        return jsonify(result.to_dict()), 200

    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to disable source: %s error=%s", source_id, exc)
        return jsonify({
            "error": "Internal server error",
            "message": str(exc),
        }), 500


def register_sources_blueprint(app: Any) -> None:
    app.register_blueprint(sources_bp)
    logger.info("Sources blueprint registered")
