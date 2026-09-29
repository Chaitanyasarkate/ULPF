"""Firewall syslog simulator for ULPF Phase 1."""

from __future__ import annotations

import logging
import random
import socket
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger("ulpf.simulators.firewall")

_ACTIONS = ["ALLOW", "DENY", "DROP", "ACCEPT"]
_PROTOCOLS = ["TCP", "UDP", "ICMP"]
_DEVICES = ["fw-edge-01", "fw-edge-02", "fw-dmz-01", "fw-int-01"]
_FACILITIES = ["kern", "user", "mail", "daemon", "auth", "syslog", "local0"]
_SEVERITIES = range(8)


def _generate_event() -> str:
    device = random.choice(_DEVICES)
    action = random.choice(_ACTIONS)
    protocol = random.choice(_PROTOCOLS)
    src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    dst_ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([22, 80, 443, 3389, 8080, 53])
    severity = random.choice(_SEVERITIES)
    facility = random.choice(_FACILITIES)
    timestamp = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")

    if protocol == "ICMP":
        return (
            f"<{severity*8 + _FACILITIES.index(facility)}>"
            f"{timestamp} {device} %ASA-6-302013: {action} inbound {protocol} "
            f"src={src_ip} dst={dst_ip} (hitcnt=0)"
        )
    return (
        f"<{severity*8 + _FACILITIES.index(facility)}>"
        f"{timestamp} {device} %ASA-6-302013: {action} inbound {protocol} "
        f"src={src_ip}:{src_port} dst={dst_ip}:{dst_port} (hitcnt=0)"
    )


class FirewallSimulator:
    """Continuously generate firewall syslog events and send them via UDP."""

    def __init__(self, target_host: str = "127.0.0.1", target_port: int = 5514) -> None:
        self.target_host = target_host
        self.target_port = target_port
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self, interval: float = 1.0) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, args=(interval,), daemon=True)
        self._thread.start()
        logger.info("Firewall simulator started (target=%s:%s)", self.target_host, self.target_port)

    def _run(self, interval: float) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while self._running:
            event = _generate_event()
            try:
                sock.sendto(event.encode("utf-8"), (self.target_host, self.target_port))
                logger.debug("Sent firewall event: %s", event[:80])
            except Exception:  # noqa: BLE001
                logger.warning("Failed to send firewall event")
            time.sleep(interval)
        sock.close()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Firewall simulator stopped")
