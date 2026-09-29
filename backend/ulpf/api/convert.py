"""Conversion API blueprint for ULPF Phase 9A.

Provides endpoints for converting normalized events to various output formats.
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify
from flask import request as flask_request

from ulpf.api.auth import require_permission
from ulpf.output.base import OutputFormat
from ulpf.output.registry import UnknownFormatError
from ulpf.output.service import ConversionError, ConversionService
from ulpf.storage.opensearch_adapter import OpenSearchAdapter

logger = logging.getLogger("ulpf.api.convert")

convert_bp = Blueprint("convert", __name__)


def register_convert_blueprint(app) -> None:
    """Register the conversion blueprint with the Flask app."""
    app.register_blueprint(convert_bp, url_prefix="/api/v1/convert")
    logger.info("Conversion endpoints registered")


@convert_bp.route("", methods=["POST"])
@require_permission("events:convert")
def convert_event():
    """Convert a normalized event to a specified output format.

    Request:
        {
            "event_id": "EVENT_ID",
            "output_format": "json" | "cef" | "leef" | "xml" | "csv" | "syslog" | "ocsf"
        }

    Response:
        {
            "event_id": "...",
            "raw_event_id": "...",
            "output_format": "...",
            "formatter_id": "...",
            "formatter_version": "...",
            "schema_version": "...",
            "conversion_timestamp": "...",
            "payload": "..."
        }
    """
    try:
        body = flask_request.get_json(force=False, silent=True)
    except Exception as exc:
        if "JSON" in str(exc) or "json" in str(exc).lower():
            logger.warning("Malformed JSON in convert request")
            return jsonify({"error": "malformed_json", "message": "Request body is not valid JSON."}), 400
        raise

    if not isinstance(body, dict):
        logger.warning("Convert request body is not a JSON object")
        return jsonify({"error": "invalid_body", "message": "Request body must be a JSON object."}), 400

    event_id = body.get("event_id")
    if not event_id or not isinstance(event_id, str):
        return jsonify({"error": "missing_event_id", "message": "Field 'event_id' is required and must be a string."}), 400

    output_format = body.get("output_format")
    if not output_format or not isinstance(output_format, str):
        return jsonify({
            "error": "missing_output_format",
            "message": "Field 'output_format' is required. Valid values: json, cef, leef, xml, csv, syslog, ocsf.",
        }), 400

    try:
        OutputFormat.from_string(output_format)
    except ValueError:
        valid_formats = ", ".join(f.value for f in OutputFormat)
        return jsonify({
            "error": "unsupported_format",
            "message": f"Unsupported output format '{output_format}'. Valid values: {valid_formats}",
        }), 400

    try:
        import asyncio
        async def fetch_event():
            adapter = OpenSearchAdapter()
            try:
                return await adapter.get_event(event_id)
            finally:
                await adapter.close()

        event_data = asyncio.run(fetch_event())
    except Exception as exc:  # noqa: BLE001 - API error handling
        logger.error("Failed to fetch event from storage: %s", exc)
        return jsonify({"error": "storage_error", "message": "Failed to retrieve event from storage."}), 500

    if not event_data:
        return jsonify({"error": "not_found", "message": f"Event '{event_id}' not found."}), 404

    try:
        from ulpf.common.models import NormalizedEvent
        normalized = NormalizedEvent(
            event_id=event_data.get("event_id", ""),
            raw_event_id=event_data.get("raw_event_id", ""),
            source_id=event_data.get("source_id", ""),
            source_type=event_data.get("source_type", ""),
            format=event_data.get("format", ""),
            parser_id=event_data.get("parser_id", ""),
            parser_version=event_data.get("parser_version", ""),
            schema_version=event_data.get("schema_version", "1.0.0"),
            event_timestamp=event_data.get("event_timestamp"),
            ingestion_timestamp=event_data.get("ingestion_timestamp", ""),
            sha256=event_data.get("sha256", ""),
            ocsf=event_data.get("ocsf", {}),
            parsed_fields=event_data.get("parsed_fields", {}),
            raw_payload=event_data.get("raw_payload", ""),
        )
    except Exception as exc:  # noqa: BLE001 - API error handling
        logger.error("Failed to create NormalizedEvent: %s", exc)
        return jsonify({"error": "internal_error", "message": "Failed to process event data."}), 500

    try:
        service = ConversionService()
        result = service.convert(normalized, output_format)
        return jsonify(result.to_dict()), 200
    except UnknownFormatError as exc:
        return jsonify({"error": "unsupported_format", "message": str(exc)}), 400
    except ConversionError as exc:
        logger.error("Conversion failed for event %s: %s", event_id, exc)
        return jsonify({"error": "conversion_error", "message": str(exc)}), 500


@convert_bp.route("/formats", methods=["GET"])
@require_permission("events:view")
def list_formats():
    """List available output formats with metadata."""
    try:
        service = ConversionService()
        formats = service.get_available_formats()
        return jsonify({"formats": formats}), 200
    except Exception as exc:  # noqa: BLE001 - API error handling
        logger.error("Failed to list formats: %s", exc)
        return jsonify({"error": "internal_error", "message": "Failed to list formats."}), 500


@convert_bp.route("/health", methods=["GET"])
@require_permission("health:view")
def convert_health():
    """Health check for conversion service."""
    return jsonify({"status": "ok", "service": "conversion"}), 200
