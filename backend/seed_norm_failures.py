"""Seed many normalization failures into Kafka for prototype demo."""
import json
import uuid
from datetime import datetime, timezone

from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers="localhost:9092",
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    key_serializer=lambda v: v.encode("utf-8"),
)

for i in range(10000):
    raw_event_id = str(uuid.uuid4())
    envelope = {
        "event_id": raw_event_id,
        "raw_event_id": raw_event_id,
        "source_id": f"sim-router-{i}",
        "source_type": "router",
        "format": "json",
        "received_at": datetime.now(timezone.utc).isoformat(),
        "processing_status": "failed",
        "error": {
            "stage": "normalizer",
            "code": "E_NO_NORMALIZER",
            "message": f"No normalizer available for source_type=router format=json"
        },
        "parsed": {
            "event_id": raw_event_id,
            "raw_event_id": raw_event_id,
            "source_id": f"sim-router-{i}",
            "source_type": "router",
            "format": "json",
            "parser_id": "router_json_v1",
            "parser_version": "1.0.0",
            "schema_version": "1.0.0",
            "event_timestamp": datetime.now(timezone.utc).isoformat(),
            "extracted": {"malformed": True}
        },
        "raw": {
            "raw_event_id": raw_event_id,
            "source_id": f"sim-router-{i}",
            "source_type": "router",
            "format": "json",
            "payload": '{"malformed": true}',
            "received_at": datetime.now(timezone.utc).isoformat()
        },
        "sha256": "0" * 64,
        "parser_id": "router_json_v1",
        "parser_version": "1.0.0",
        "schema_version": "1.0.0",
    }
    producer.send("failed-events", key=raw_event_id, value=envelope)

producer.flush()
producer.close()
print("Done - seeded 10000 normalization failures")