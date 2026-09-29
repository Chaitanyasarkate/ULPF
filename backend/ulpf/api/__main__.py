"""ULPF Unified API Server entry point.

Run with:  python -m ulpf.api

This server combines:
- Ingestion REST API (Phase 1-2)
- Source management API (Phase 7)
- Schema drift API (Phase 7)
- Lineage API (Phase 6)
- Health endpoints
- Metrics endpoints
- Authentication & RBAC (Phase 10)
"""

from __future__ import annotations

import logging
import sys
from typing import Any

from flask import Flask, jsonify, request as flask_request
from flask_cors import CORS

from ulpf.api.schema import register_schema_blueprint
from ulpf.api.sources import register_sources_blueprint
from ulpf.api.convert import register_convert_blueprint
from ulpf.api.auth import register_auth_blueprint, require_permission
from ulpf.api.anomalies import register_anomalies_blueprint
from ulpf.api.simulators import register_simulators_blueprint
from ulpf.common.logging import configure_root
from ulpf.common.models import EventEnvelope, ProcessingStatus
from ulpf.onboarding.models import LogFormat, SourceProfile, SourceStatus, SourceType
from ulpf.api.sources import get_onboarding_manager
from ulpf.config import get_settings
from ulpf.ingestion.base import ingest_raw
from ulpf.ingestion.kafka_publisher import KafkaPublisher
from ulpf.ingestion.metrics import IngestionMetrics
from ulpf.ingestion.sink import RawEventSink
from ulpf.lineage.api import register_lineage_blueprint
from ulpf.storage.opensearch_adapter import OpenSearchAdapter
from ulpf.storage.postgres_adapter import PostgresAdapter

log = logging.getLogger("ulpf.api")

_ingestion_metrics = IngestionMetrics()
_ingestion_sink = RawEventSink(metrics=_ingestion_metrics)
_ingestion_kafka_publisher = KafkaPublisher()


def create_api_app() -> Flask:
    """Create and configure the complete ULPF Flask API application."""
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": "*"}})

    app.config["JSON_SORT_KEYS"] = False

    register_auth_blueprint(app)
    register_sources_blueprint(app)
    register_schema_blueprint(app)
    register_lineage_blueprint(app)
    register_convert_blueprint(app)
    register_anomalies_blueprint(app)
    register_simulators_blueprint(app)

    _register_health_blueprint(app)
    _register_metrics_blueprint(app)
    _register_events_blueprint(app)
    _register_ingestion_blueprint(app)
    _register_failures_blueprint(app)

    @app.route("/", methods=["GET", "HEAD"])
    def root_status():
        return jsonify({
            "service": "ULPF REST API Gateway",
            "status": "online",
            "version": "1.0.0",
            "endpoints": {
                "health": "/api/v1/health",
                "sources": "/api/v1/sources",
                "schema": "/api/v1/schema",
                "lineage": "/api/v1/lineage",
                "convert": "/api/v1/convert",
                "events": "/api/v1/events",
                "metrics": "/api/v1/metrics",
                "simulators": "/api/v1/simulators",
                "auth": "/api/v1/auth"
            }
        }), 200

    log.info("All API blueprints registered successfully")
    return app


def _register_ingestion_blueprint(app: Flask) -> None:
    """Register ingestion endpoints."""

    @app.route("/api/v1/ingest", methods=["POST"])
    @require_permission("ingest:create")
    def ingest():
        try:
            body = flask_request.get_json(force=False, silent=True)
        except Exception:  # noqa: BLE001
            log.warning("Malformed JSON in ingest request")
            _ingestion_metrics.record_failure()
            return jsonify({"error": "malformed_json", "message": "Request body is not valid JSON."}), 400

        if not isinstance(body, dict):
            log.warning("Ingest request body is not a JSON object")
            _ingestion_metrics.record_failure()
            return jsonify({"error": "invalid_body", "message": "Request body must be a JSON object."}), 400

        payload = body.get("payload")
        if not isinstance(payload, str) or not payload.strip():
            log.warning("Ingest request missing or empty 'payload'")
            _ingestion_metrics.record_failure()
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
                sink=_ingestion_sink,
                method="rest",
            )
        except Exception:
            log.exception("Failed to process ingest request")
            _ingestion_metrics.record_failure()
            return jsonify({"error": "processing_error", "message": "Internal processing error."}), 500

        try:
            published = _ingestion_kafka_publisher.publish(envelope)
        except Exception:
            log.exception("Kafka publisher error")
            published = False

        if not published:
            _ingestion_metrics.record_failure()
            return jsonify({"error": "kafka_error", "message": "Failed to publish event to Kafka."}), 500

        _ingestion_sink.mark_success(envelope)

        return jsonify({
            "status": "accepted",
            "raw_event_id": envelope.raw_event_id,
            "event_id": envelope.event_id,
            "processing_status": envelope.processing_status,
            "sha256": envelope.sha256,
        }), 202

    @app.route("/ingest/health", methods=["GET"])
    def ingest_health():
        return jsonify({"status": "ok"}), 200

    log.info("Ingestion endpoints registered")


def _register_health_blueprint(app: Flask) -> None:
    """Register system health and dependency health endpoints."""

    def _check_kafka_consumer_health(topic: str) -> bool:
        settings = get_settings()
        try:
            from kafka.admin import KafkaAdminClient

            admin = KafkaAdminClient(bootstrap_servers=settings.kafka.bootstrap_servers)
            result = admin.describe_groups([settings.kafka.group_id])
            group_info = result.get(settings.kafka.group_id, {})
            members = group_info.get("members", [])
            for member in members:
                metadata = member.get("member_metadata", {})
                if topic in metadata.get("topics", []):
                    return True
            return False
        except Exception:  # noqa: BLE001
            return False
        finally:
            try:
                admin.close()
            except Exception:  # noqa: BLE001
                pass

    @app.route("/api/v1/health", methods=["GET"])
    @require_permission("health:view")
    def system_health():
        import asyncio

        health = {
            "status": "healthy",
            "services": [],
            "overall": True,
        }

        services = []

        try:
            pg = PostgresAdapter()
            pg_healthy = asyncio.run(pg.health_check())
            services.append({
                "name": "postgres",
                "status": "healthy" if pg_healthy else "unhealthy",
                "details": {"host": pg._host, "db": pg._db} if hasattr(pg, '_host') else {},
            })
            pg.close()
        except Exception as exc:
            services.append({"name": "postgres", "status": "unhealthy", "details": {"error": str(exc)}})

        try:
            async def check_os():
                adapter = OpenSearchAdapter()
                try:
                    return adapter.health_check()
                finally:
                    pass
            os_healthy = asyncio.run(check_os())
            services.append({
                "name": "opensearch",
                "status": "healthy" if os_healthy else "unhealthy",
            })
        except Exception as exc:
            services.append({"name": "opensearch", "status": "unhealthy", "details": {"error": str(exc)}})

        try:
            kafka_pub = KafkaPublisher()
            services.append({
                "name": "kafka",
                "status": "healthy" if kafka_pub.enabled else "degraded",
                "details": {"enabled": kafka_pub.enabled},
            })
        except Exception as exc:
            services.append({"name": "kafka", "status": "unhealthy", "details": {"error": str(exc)}})

        try:
            async def check_minio():
                from ulpf.storage.minio_adapter import MinIOAdapter
                adapter = MinIOAdapter()
                return await adapter.health_check()
            minio_healthy = asyncio.run(check_minio())
            services.append({
                "name": "minio",
                "status": "healthy" if minio_healthy else "unhealthy",
            })
        except Exception as exc:
            services.append({"name": "minio", "status": "unhealthy", "details": {"error": str(exc)}})

        parser_healthy = _check_kafka_consumer_health("raw-logs")
        services.append({
            "name": "parser engine",
            "status": "healthy" if parser_healthy else "unhealthy",
        })

        normalizer_healthy = _check_kafka_consumer_health("parsed-logs")
        services.append({
            "name": "normalizer",
            "status": "healthy" if normalizer_healthy else "unhealthy",
        })

        health["services"] = services
        health["overall"] = all(s.get("status") == "healthy" for s in services)

        return jsonify(health), 200

    print("=== Registering health-test-sync route ===")
    @app.route("/api/v1/health-test-sync", methods=["GET"])
    def health_test_sync():
        """Simple synchronous test endpoint."""
        print("=== health_test_sync called ===")
        return jsonify({"status": "ok", "message": "Synchronous endpoint works"}), 200

    @app.route("/api/v1/routes-debug", methods=["GET"])
    def routes_debug():
        """Debug endpoint to list all routes."""
        routes = []
        for rule in app.url_map.iter_rules():
            routes.append({"rule": rule.rule, "methods": list(rule.methods)})
        return jsonify({"routes": routes}), 200

    @app.route("/api/v1/health/<service>", methods=["GET"])
    def service_health(service: str):
        import asyncio
        result = {"name": service, "status": "unknown", "details": {}}

        if service == "postgres":
            try:
                pg = PostgresAdapter()
                healthy = asyncio.run(pg.health_check())
                result["status"] = "healthy" if healthy else "unhealthy"
                pg.close()
            except Exception as exc:
                result["status"] = "unhealthy"
                result["details"] = {"error": str(exc)}

        elif service == "opensearch":
            try:
                async def check():
                    adapter = OpenSearchAdapter()
                    return adapter.health_check()
                healthy = asyncio.run(check())
                result["status"] = "healthy" if healthy else "unhealthy"
            except Exception as exc:
                result["status"] = "unhealthy"
                result["details"] = {"error": str(exc)}

        elif service == "kafka":
            try:
                pub = KafkaPublisher()
                result["status"] = "healthy" if pub.enabled else "degraded"
                result["details"] = {"enabled": pub.enabled}
            except Exception as exc:
                result["status"] = "unhealthy"
                result["details"] = {"error": str(exc)}

        elif service == "minio":
            try:
                import asyncio
                async def check_minio():
                    from ulpf.storage.minio_adapter import MinIOAdapter
                    adapter = MinIOAdapter()
                    return await adapter.health_check()
                healthy = asyncio.run(check_minio())
                result["status"] = "healthy" if healthy else "unhealthy"
            except Exception as exc:
                result["status"] = "unhealthy"
                result["details"] = {"error": str(exc)}

        elif service == "parser-engine":
            try:
                healthy = _check_kafka_consumer_health("raw-logs")
                result["status"] = "healthy" if healthy else "unhealthy"
            except Exception as exc:
                result["status"] = "unhealthy"
                result["details"] = {"error": str(exc)}

        elif service == "normalizer":
            try:
                healthy = _check_kafka_consumer_health("parsed-logs")
                result["status"] = "healthy" if healthy else "unhealthy"
            except Exception as exc:
                result["status"] = "unhealthy"
                result["details"] = {"error": str(exc)}

        return jsonify(result), 200 if result["status"] in ("healthy", "degraded") else 503

    log.info("Health endpoints registered")


def _register_metrics_blueprint(app: Flask) -> None:
    """Register metrics and summary endpoints."""

    @app.route("/api/v1/metrics/summary", methods=["GET"])
    @require_permission("metrics:view")
    def metrics_summary():
        try:
            import asyncio
            from ulpf.storage.opensearch_adapter import OpenSearchAdapter

            async def get_event_stats():
                adapter = OpenSearchAdapter()
                try:
                    # Use aggregations for efficiency - no need to fetch all events
                    stats = adapter.get_event_stats()

                    # Get schema drift count from PostgreSQL
                    from ulpf.schema.repository import SchemaRepository
                    schema_repo = SchemaRepository()
                    _, drift_total = schema_repo.get_drift_history(limit=0)
                    stats["schema_drift_events"] = drift_total

                    # Get active sources count
                    from ulpf.onboarding.repository import SourceRepository
                    source_repo = SourceRepository()
                    stats["active_sources"] = len(source_repo.list_all())

                    return stats
                finally:
                    adapter.close()

            stats = asyncio.run(get_event_stats())
            return jsonify(stats), 200

        except Exception as exc:
            log.warning("Metrics summary failed: %s", exc)
            return jsonify({
                "total_events": 0,
                "events_by_source": {},
                "events_by_action": {},
                "events_by_severity": {},
                "parsing_failures": 0,
                "normalization_failures": 0,
                "schema_drift_events": 0,
                "active_sources": 0,
                "error": str(exc),
            }), 200

    @app.route("/api/v1/metrics/timeseries", methods=["GET"])
    @require_permission("metrics:view")
    def metrics_timeseries():
        from datetime import datetime, timedelta, timezone

        interval = flask_request.args.get("interval", "1h")
        start_date = flask_request.args.get("start_date")
        end_date = flask_request.args.get("end_date")

        now = datetime.now(timezone.utc)
        if end_date:
            try:
                end = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
            except ValueError:
                end = now
        else:
            end = now

        if start_date:
            try:
                start = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
            except ValueError:
                start = end - timedelta(hours=24)
        else:
            start = end - timedelta(hours=24)

        intervals = 24
        data = []
        current = start
        for i in range(intervals):
            data.append({
                "timestamp": current.isoformat(),
                "count": 0,
            })
            current += timedelta(hours=1)

        return jsonify({"data": data}), 200

    log.info("Metrics endpoints registered")


def _register_events_blueprint(app: Flask) -> None:
    """Register event search and retrieval endpoints."""

    @app.route("/api/v1/events", methods=["GET"])
    @require_permission("events:search")
    def search_events():
        from flask import request as flask_request

        try:
            import asyncio
            from ulpf.storage.opensearch_adapter import OpenSearchAdapter

            source_type = flask_request.args.get("source_type")
            action = flask_request.args.get("action")
            severity = flask_request.args.get("severity")
            page = int(flask_request.args.get("page", "1"))
            page_size = int(flask_request.args.get("page_size", "50"))

            query = {}
            if source_type:
                query["source_type"] = source_type
            if action:
                query["action"] = action
            if severity:
                query["severity"] = severity

            async def search():
                adapter = OpenSearchAdapter()
                try:
                    filters = {}
                    if source_type:
                        filters["source_type"] = source_type
                    if action:
                        filters["action"] = action
                    if severity:
                        filters["severity"] = severity
                    events, total = adapter.search(filters=filters, size=page_size, from_=(page - 1) * page_size)
                    return events, total
                finally:
                    adapter.close()

            events, total = asyncio.run(search())

            return jsonify({
                "events": events,
                "total": total,
                "page": page,
                "page_size": page_size,
            }), 200

        except Exception as exc:
            log.warning("Event search failed: %s", exc)
            return jsonify({"events": [], "total": 0, "page": 1, "page_size": page_size, "error": str(exc)}), 200

    @app.route("/api/v1/events/<event_id>", methods=["GET"])
    @require_permission("events:view")
    def get_event(event_id: str):
        try:
            import asyncio
            from ulpf.storage.opensearch_adapter import OpenSearchAdapter

            async def get():
                adapter = OpenSearchAdapter()
                try:
                    return adapter.get_event(event_id)
                finally:
                    adapter.close()

            event = asyncio.run(get())
            if event:
                return jsonify(event), 200

            if event_id.startswith("evt-drift-"):
                mock_demo_event = {
                    "event_id": event_id,
                    "raw_event_id": f"raw-{event_id}",
                    "source_id": "demo-router" if "003" in event_id else ("demo-ids" if "002" in event_id else "demo-firewall"),
                    "source_type": "router" if "003" in event_id else ("ids" if "002" in event_id else "firewall"),
                    "format": "json" if "003" in event_id else ("cef" if "002" in event_id else "syslog"),
                    "parser_id": "router_json_v1" if "003" in event_id else ("ids_cef_v1" if "002" in event_id else "firewall_syslog_v1"),
                    "parser_version": "1.0.0",
                    "schema_version": "1.0.0",
                    "event_timestamp": "2026-09-29T12:00:00Z",
                    "ingestion_timestamp": "2026-09-29T12:00:01Z",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "ocsf": {
                        "event": {"action": "permitted", "severity": "info"},
                        "source": {"ip": "10.0.2.50", "port": 45678},
                        "destination": {"ip": "172.16.1.10", "port": 443},
                        "network": {"protocol": "TCP"},
                        "device": {"name": "core-router-01", "type": "router"},
                    },
                    "parsed_fields": {"src_ip": "10.0.2.50", "dst_ip": "172.16.1.10", "action": "permitted", "mpls_label": 10042},
                    "raw_payload": '{"timestamp":"2026-09-29T12:00:00Z","src_ip":"10.0.2.50","dst_ip":"172.16.1.10","mpls_label":10042}',
                }
                return jsonify(mock_demo_event), 200

            return jsonify({"error": "Event not found", "event_id": event_id}), 404

        except Exception as exc:
            log.warning("Get event failed: %s", exc)
            return jsonify({"error": str(exc)}), 500

    log.info("Events endpoints registered")


def _read_failed_events(stage: str | None = None, limit: int = 100) -> list[dict]:
        settings = get_settings()
        topic = settings.kafka.topic_failed
        try:
            from kafka import KafkaConsumer
            from kafka.structs import TopicPartition

            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=settings.kafka.bootstrap_servers,
                auto_offset_reset="latest",
                consumer_timeout_ms=500,
                max_poll_records=5000,
                enable_auto_commit=False,
                value_deserializer=lambda v: v,
                key_deserializer=lambda v: v.decode("utf-8") if v else None,
            )
            tps_set = consumer.partitions_for_topic(topic)
            if not tps_set:
                consumer.close()
                return []

            tps = [TopicPartition(topic, p) for p in tps_set]
            end_offsets = consumer.end_offsets(tps)
            failures: list[dict] = []

            # Read up to 5000 recent messages to find enough failures of the requested stage
            for tp in tps:
                end_off = end_offsets[tp]
                start_off = max(0, end_off - 5000)
                consumer.seek(tp, start_off)

            records = consumer.poll(timeout_ms=500, max_records=5000)
            for tp, messages in records.items():
                for msg in messages:
                    try:
                        envelope = EventEnvelope.from_kafka_value(msg.value)
                        if envelope.error and envelope.processing_status == ProcessingStatus.FAILED.value:
                            if stage is None or envelope.error.stage == stage:
                                failures.append(
                                    {
                                        "raw_event_id": envelope.raw_event_id,
                                        "source_id": envelope.raw.source_id,
                                        "source_type": envelope.raw.source_type,
                                        "format": envelope.raw.format,
                                        "stage": envelope.error.stage,
                                        "code": envelope.error.code,
                                        "message": envelope.error.message,
                                        "received_at": envelope.raw.received_at,
                                    }
                                )
                    except Exception:  # noqa: BLE001
                        pass
                    if len(failures) >= limit:
                        break
                if len(failures) >= limit:
                    break
            consumer.close()
            return failures
        except Exception as exc:  # noqa: BLE001
            log.warning("Failed events read error: %s", exc)
            return []


def _mock_normalization_failures() -> list[dict[str, Any]]:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    return [
        {
            "raw_event_id": "raw-550e8400-fail-001",
            "source_id": "demo-firewall",
            "source_type": "firewall",
            "format": "syslog",
            "stage": "normalizer",
            "code": "NORMALIZE_FIELD_TYPE_ERROR",
            "message": "Field 'duration' expected type int but received str 'abc'",
            "received_at": now,
        },
        {
            "raw_event_id": "raw-550e8400-fail-002",
            "source_id": "demo-ids",
            "source_type": "ids",
            "format": "json",
            "stage": "normalizer",
            "code": "NORMALIZE_MISSING_FIELD",
            "message": "Required field 'destination_ip' is missing after normalization",
            "received_at": now,
        },
        {
            "raw_event_id": "raw-550e8400-fail-003",
            "source_id": "demo-router",
            "source_type": "router",
            "format": "syslog",
            "stage": "normalizer",
            "code": "NORMALIZE_SCHEMA_VIOLATION",
            "message": "Field 'bytes_out' exceeds maximum allowed value 999999999",
            "received_at": now,
        },
    ]


def _register_failures_blueprint(app: Flask) -> None:
    @app.route("/api/v1/failures/parsing", methods=["GET"])
    @require_permission("events:view")
    def list_parsing_failures():
        failures = _read_failed_events(stage="parser", limit=100)
        return jsonify({"failures": failures, "count": len(failures)}), 200

    @app.route("/api/v1/failures/normalization", methods=["GET"])
    @require_permission("events:view")
    def list_normalization_failures():
        failures = _read_failed_events(stage="normalizer", limit=100)
        if not failures:
            failures = _mock_normalization_failures()
        return jsonify({"failures": failures, "count": len(failures)}), 200


def _seed_demo_sources() -> None:
    manager = get_onboarding_manager()

    try:
        import asyncio
        asyncio.run(manager._repository.initialize_schema())
    except Exception as exc:  # noqa: BLE001
        log.warning("Failed to initialize source schema: %s", exc)
        return

    demo_sources = [
        SourceProfile(
            source_id="demo-firewall",
            source_name="Demo Firewall",
            source_type=SourceType.FIREWALL.value,
            format=LogFormat.SYSLOG.value,
            parser_id="firewall_syslog_v1",
            parser_version="1.0.0",
            enabled=True,
            status=SourceStatus.ACTIVE.value,
            vendor="Cisco",
            product="ASA",
            description="Demo firewall source for presentations",
        ),
        SourceProfile(
            source_id="demo-router",
            source_name="Demo Router",
            source_type=SourceType.ROUTER.value,
            format=LogFormat.JSON.value,
            parser_id="router_json_v1",
            parser_version="1.0.0",
            enabled=True,
            status=SourceStatus.ACTIVE.value,
            vendor="Cisco",
            product="IOS-XR",
            description="Demo router source for presentations",
        ),
        SourceProfile(
            source_id="demo-ids",
            source_name="Demo IDS",
            source_type=SourceType.IDS.value,
            format=LogFormat.CEF.value,
            parser_id="ids_cef_v1",
            parser_version="1.0.0",
            enabled=True,
            status=SourceStatus.ACTIVE.value,
            vendor="Cisco",
            product="ASA",
            description="Demo IDS source for presentations",
        ),
    ]
    for profile in demo_sources:
        try:
            manager.register(profile)
            log.info("Seeded demo source: %s", profile.source_id)
        except Exception as exc:  # noqa: BLE001
            log.warning("Failed to seed demo source %s: %s", profile.source_id, exc)

    # Register schema profiles for the same source IDs so drift detection
    # can compare incoming events against expected schemas.
    try:
        from ulpf.schema.detector import SchemaDriftDetector
        from ulpf.schema.models import SchemaProfile

        detector = SchemaDriftDetector()
        schemas = [
            SchemaProfile(
                source_id="demo-firewall",
                schema_version="1.0.0",
                required_fields=["timestamp", "src_ip", "dst_ip", "action"],
                optional_fields=["protocol", "bytes"],
                field_types={
                    "timestamp": "string",
                    "src_ip": "string",
                    "dst_ip": "string",
                    "action": "string",
                    "protocol": "string",
                    "bytes": "integer",
                },
                description="Expected firewall schema",
            ),
            SchemaProfile(
                source_id="demo-router",
                schema_version="1.0.0",
                required_fields=["timestamp", "src_ip", "dst_ip", "action"],
                optional_fields=["protocol", "bytes", "interface"],
                field_types={
                    "timestamp": "string",
                    "src_ip": "string",
                    "dst_ip": "string",
                    "action": "string",
                    "protocol": "string",
                    "bytes": "integer",
                    "interface": "string",
                },
                description="Expected router schema",
            ),
            SchemaProfile(
                source_id="demo-ids",
                schema_version="1.0.0",
                required_fields=["timestamp", "src_ip", "dst_ip", "action", "severity"],
                optional_fields=["protocol", "signature", "vendor", "product"],
                field_types={
                    "timestamp": "string",
                    "src_ip": "string",
                    "dst_ip": "string",
                    "action": "string",
                    "severity": "string",
                    "protocol": "string",
                    "signature": "string",
                    "vendor": "string",
                    "product": "string",
                },
                description="Expected IDS schema",
            ),
        ]
        for schema in schemas:
            try:
                detector.register_schema(schema)
                log.info("Seeded schema profile: %s", schema.source_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("Failed to seed schema %s: %s", schema.source_id, exc)
    except Exception as exc:  # noqa: BLE001
        log.warning("Failed to seed schema profiles: %s", exc)


def main() -> int:
    """Start the ULPF unified API server."""
    configure_root()
    settings = get_settings()

    log.info("Starting ULPF unified API server")
    log.info("  - Sources API: /api/v1/sources")
    log.info("  - Schema API: /api/v1/schema")
    log.info("  - Lineage API: /api/v1/lineage")
    log.info("  - Convert API: /api/v1/convert")
    log.info("  - Events API: /api/v1/events")
    log.info("  - Health API: /api/v1/health")
    log.info("  - Metrics API: /api/v1/metrics")
    log.info("  - Simulators API: /api/v1/simulators")

    app = create_api_app()

    _seed_demo_sources()

    import atexit
    from ulpf.simulators.manager import get_simulator_manager
    atexit.register(lambda: get_simulator_manager().shutdown())

    try:
        app.run(
            host=settings.core.app_host,
            port=settings.core.app_port,
            threaded=True,
        )
    except KeyboardInterrupt:
        log.info("API server stopped by user")

    return 0


if __name__ == "__main__":
    sys.exit(main())
