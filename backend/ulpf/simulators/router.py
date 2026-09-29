"""Router JSON/REST simulator for ULPF Phase 1."""

from __future__ import annotations

import json
import logging
import random
import threading
import time
from datetime import datetime, timezone

import requests

from ulpf.common.models import SourceType

logger = logging.getLogger("ulpf.simulators.router")

_INTERFACES = ["GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet0/2", "TenGigE0/1"]
_ACTIONS = ["permitted", "denied", "dropped"]


def _generate_event() -> dict:
    src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    dst_ip = f"172.16.{random.randint(0,255)}.{random.randint(1,254)}"
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 53, 22, 3389, 8080]),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "action": random.choice(_ACTIONS),
        "interface": random.choice(_INTERFACES),
        "bytes": random.randint(64, 65535),
    }


class RouterSimulator:
    """Continuously generate router JSON events and POST them to the REST ingest API."""

    def __init__(self, rest_url: str = "http://127.0.0.1:8000/api/v1/ingest") -> None:
        self.rest_url = rest_url
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self, interval: float = 1.0) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, args=(interval,), daemon=True)
        self._thread.start()
        logger.info("Router simulator started (target=%s)", self.rest_url)

    def _run(self, interval: float) -> None:
        session = requests.Session()
        while self._running:
            event = _generate_event()
            try:
                payload = {
                    "payload": json.dumps(event),
                    "source_id": "router-core-01",
                    "source_type": SourceType.ROUTER.value,
                    "format": "json",
                }
                resp = session.post(self.rest_url, json=payload, timeout=5)
                if resp.status_code not in (200, 202):
                    logger.warning("Router ingest returned %s: %s", resp.status_code, resp.text)
            except Exception:  # noqa: BLE001
                logger.warning("Failed to send router event")
            time.sleep(interval)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Router simulator stopped")
