"""Live random demo event generator for ULPF presentations.

Run with:  python -m ulpf.simulators.demo

Continuously emits a random mix of:
- valid firewall / router / IDS events (successful pipeline)
- malformed / unsupported logs (real parsing failures)
- schema-drift events (via existing schema repository)
"""

from __future__ import annotations

import json
import logging
import random
import time
import uuid
from datetime import datetime, timezone

import requests

from ulpf.config import get_settings
from ulpf.schema.models import DriftDetectionResult, DriftType, DriftSeverity, SchemaProfile
from ulpf.schema.repository import SchemaRepository

logger = logging.getLogger("ulpf.simulators.demo")

REST_URL = "http://127.0.0.1:8000/api/v1/ingest"

_VALID_ACTIONS = ["ALLOW", "DENY", "DROP", "ACCEPT"]
_VALID_PROTOCOLS = ["TCP", "UDP", "ICMP"]
_VALID_SEVERITIES = ["low", "medium", "high", "critical"]
_VALID_INTERFACES = ["GigabitEthernet0/0", "GigabitEthernet0/1", "TenGigE0/1"]


def _random_ip() -> str:
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _random_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _post(payload: str, source_id: str, source_type: str, fmt: str) -> bool:
    try:
        resp = requests.post(
            REST_URL,
            json={
                "payload": payload,
                "source_id": source_id,
                "source_type": source_type,
                "format": fmt,
            },
            timeout=5,
        )
        return resp.status_code == 202
    except Exception:  # noqa: BLE001
        return False


def _valid_firewall() -> bool:
    ts = _random_ts()
    src = _random_ip()
    dst = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    action = random.choice(_VALID_ACTIONS)
    proto = random.choice(_VALID_PROTOCOLS)
    sport = random.randint(1024, 65535)
    dport = random.choice([22, 80, 443, 3389, 8080, 53])
    prio = random.randint(0, 191)
    payload = (
        f"<{prio}>Sep {random.randint(1,30):02d} {random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d} "
        f"fw-demo-{random.randint(1,5)} %ASA-6-302013: {action} inbound {proto} "
        f"src={src}:{sport} dst={dst}:{dport} (hitcnt=0)"
    )
    return _post(payload, f"fw-demo-{random.randint(1,5)}", "firewall", "syslog")


def _valid_router() -> bool:
    return _post(
        json.dumps({
            "timestamp": _random_ts(),
            "src_ip": _random_ip(),
            "dst_ip": f"172.16.{random.randint(0,255)}.{random.randint(1,254)}",
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 53, 22, 3389, 8080]),
            "protocol": random.choice(_VALID_PROTOCOLS),
            "action": random.choice(["permitted", "denied", "dropped"]),
            "interface": random.choice(_VALID_INTERFACES),
            "bytes": random.randint(64, 65535),
        }),
        f"router-demo-{random.randint(1,3)}",
        "router",
        "json",
    )


def _valid_ids() -> bool:
    return _post(
        "CEF:0|Cisco|ASA|1.0|1000|SQL Injection Attempt|5|"
        f"rt={datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')} "
        f"src={_random_ip()} dst=192.168.{random.randint(0,255)}.{random.randint(1,254)} "
        f"act=blocked proto=TCP",
        "ids-demo-1",
        "ids",
        "cef",
    )


def _malformed_event() -> bool:
    choice = random.randint(0, 4)
    if choice == 0:
        return _post("", "bad-1", "firewall", "syslog")
    if choice == 1:
        return _post("not json at all {{{", "bad-2", "router", "json")
    if choice == 2:
        return _post("this is just garbage text", "bad-3", "ids", "cef")
    if choice == 3:
        return _post("<58>broken syslog", "bad-4", "unknown", "unknown")
    return _post("CEF:0|broken", "bad-5", "ids", "cef")


def _schema_drift_event() -> None:
    try:
        repo = SchemaRepository()
        source_id = f"demo-drift-{random.randint(1,3)}"
        schema = SchemaProfile(
            source_id=source_id,
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
        )
        repo.upsert(schema)

        drift_types = []
        new_fields = []
        missing_required = []
        type_changes = []

        roll = random.randint(0, 2)
        if roll == 0:
            new_fields.append("new_field_1")
            drift_types.append(DriftType.NEW_FIELD.value)
        elif roll == 1:
            missing_required.append(random.choice(["timestamp", "src_ip", "dst_ip", "action"]))
            drift_types.append(DriftType.MISSING_REQUIRED_FIELD.value)
        else:
            type_changes.append({"field": "bytes", "expected_type": "integer", "actual_type": "string"})
            drift_types.append(DriftType.TYPE_CHANGE.value)

        result = DriftDetectionResult(
            source_id=source_id,
            schema_version=schema.schema_version,
            event_id=str(uuid.uuid4()),
            drift_detected=True,
            drift_types=drift_types,
            new_fields=new_fields,
            missing_required_fields=missing_required,
            missing_optional_fields=[],
            type_changes=type_changes,
            severity=DriftSeverity.WARNING.value if roll != 1 else DriftSeverity.ERROR.value,
            detected_at=datetime.now(timezone.utc).isoformat(),
        )
        repo.record_drift(result)
        logger.info("Injected schema drift event source=%s drift=%s", source_id, drift_types)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Schema drift injection failed: %s", exc)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s | %(message)s")
    logger.info("Starting ULPF live demo event generator...")
    logger.info("Target REST ingest: %s", REST_URL)

    sent = 0
    failed = 0
    drift = 0

    try:
        while True:
            roll = random.random()
            if roll < 0.55:
                ok = random.choice([_valid_firewall, _valid_router, _valid_ids])()
                sent += 1 if ok else 0
                failed += 0 if ok else 1
            elif roll < 0.85:
                ok = _malformed_event()
                sent += 1 if ok else 0
                failed += 0 if ok else 1
            else:
                _schema_drift_event()
                drift += 1

            logger.info("Demo stats -> sent=%d failed=%d drift=%d", sent, failed, drift)
            time.sleep(random.uniform(0.3, 1.2))
    except KeyboardInterrupt:
        logger.info("Demo generator stopped by user")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
