"""IDS/IPS CEF simulator for ULPF Phase 1."""

from __future__ import annotations

import logging
import random
import threading
import time
from datetime import datetime, timezone

import requests

from ulpf.common.models import SourceType

logger = logging.getLogger("ulpf.simulators.ids")

_VENDORS = ["Cisco", "PaloAlto", "Snort", "Suricata"]
_PRODUCTS = ["ASA", "Firewall", "IDS", "IPS"]
_SIGNATURES = [
    "ET SCAN Possible SSH Scan",
    "ET POLICY Outbound SSH Traffic",
    "SQL Injection Attempt",
    "XSS Attack Detected",
    "Brute Force Attempt",
    "Port Scan Detected",
    "Malware C2 Beacon",
    "DNS Tunneling Attempt",
]
_SEVERITIES = range(1, 11)
_ACTIONS = ["blocked", "detected", "alerted", "dropped"]


def _generate_event() -> str:
    vendor = random.choice(_VENDORS)
    product = random.choice(_PRODUCTS)
    signature = random.choice(_SIGNATURES)
    severity = random.choice(_SEVERITIES)
    src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    dst_ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    action = random.choice(_ACTIONS)
    timestamp = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")

    return (
        f"CEF:0|{vendor}|{product}|1.0|1000|{signature}|{severity}|"
        f"rt={timestamp} src={src_ip} dst={dst_ip} "
        f"act={action} proto=TCP"
    )


class IDSSimulator:
    """Continuously generate IDS/IPS CEF events and POST them to the REST ingest API."""

    def __init__(self, rest_url: str = "http://127.0.0.1:8000/api/v1/ingest") -> None:
        self.rest_url = rest_url
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self, interval: float = 1.0) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, args=(interval,), daemon=True)
        self._thread.start()
        logger.info("IDS simulator started (target=%s)", self.rest_url)

    def _run(self, interval: float) -> None:
        session = requests.Session()
        while self._running:
            event = _generate_event()
            try:
                payload = {
                    "payload": event,
                    "source_id": "ids-sensor-01",
                    "source_type": SourceType.IDS.value,
                    "format": "cef",
                }
                resp = session.post(self.rest_url, json=payload, timeout=5)
                if resp.status_code not in (200, 202):
                    logger.warning("IDS ingest returned %s: %s", resp.status_code, resp.text)
            except Exception:  # noqa: BLE001
                logger.warning("Failed to send IDS event")
            time.sleep(interval)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("IDS simulator stopped")
