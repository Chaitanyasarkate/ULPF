"""ULPF Simulator Runner.

Run with:  python -m ulpf.simulators.runner

This module starts all log source simulators:
1. Firewall Simulator (syslog UDP)
2. Router Simulator (REST API)
3. IDS Simulator (REST API)

Simulators feed events into the ingestion pipeline.
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
from typing import Any

from ulpf.common.logging import configure_root, get_logger
from ulpf.config import get_settings

log = get_logger("ulpf.simulators")


class SimulatorRunner:
    """Orchestrates all log source simulators."""

    def __init__(
        self,
        rest_url: str = "http://127.0.0.1:8000/api/v1/ingest",
        syslog_host: str = "127.0.0.1",
        syslog_port: int = 5514,
    ) -> None:
        self.settings = get_settings()
        self.rest_url = rest_url
        self.syslog_host = syslog_host
        self.syslog_port = syslog_port

        self._running = False
        self._shutdown_event = threading.Event()

        self._firewall_sim: Any = None
        self._router_sim: Any = None
        self._ids_sim: Any = None

        self._firewall_thread: threading.Thread | None = None
        self._router_thread: threading.Thread | None = None
        self._ids_thread: threading.Thread | None = None

        self._firewall_running = False
        self._router_running = False
        self._ids_running = False

    def _init_firewall_simulator(self) -> None:
        """Initialize firewall simulator (syslog UDP)."""
        log.info("Initializing Firewall Simulator (syslog UDP)...")

        from ulpf.simulators.firewall import FirewallSimulator

        self._firewall_sim = FirewallSimulator(
            target_host=self.syslog_host,
            target_port=self.syslog_port,
        )

        self._firewall_running = True
        self._firewall_thread = threading.Thread(
            target=self._run_firewall,
            daemon=True,
        )
        self._firewall_thread.start()
        log.info("Firewall Simulator started (target=%s:%s)", self.syslog_host, self.syslog_port)

    def _run_firewall(self) -> None:
        """Run firewall simulator loop."""
        try:
            self._firewall_sim.start(interval=1.0)
            while self._firewall_running:
                import time
                time.sleep(0.5)
        except Exception as exc:
            log.error("Firewall simulator error: %s", exc)

    def _init_router_simulator(self) -> None:
        """Initialize router simulator (REST API)."""
        log.info("Initializing Router Simulator (REST API)...")

        from ulpf.simulators.router import RouterSimulator

        self._router_sim = RouterSimulator(rest_url=self.rest_url)

        self._router_running = True
        self._router_thread = threading.Thread(
            target=self._run_router,
            daemon=True,
        )
        self._router_thread.start()
        log.info("Router Simulator started (target=%s)", self.rest_url)

    def _run_router(self) -> None:
        """Run router simulator loop."""
        try:
            self._router_sim.start(interval=2.0)
            while self._router_running:
                import time
                time.sleep(0.5)
        except Exception as exc:
            log.error("Router simulator error: %s", exc)

    def _init_ids_simulator(self) -> None:
        """Initialize IDS simulator (REST API)."""
        log.info("Initializing IDS Simulator (REST API)...")

        from ulpf.simulators.ids import IDSSimulator

        self._ids_sim = IDSSimulator(rest_url=self.rest_url)

        self._ids_running = True
        self._ids_thread = threading.Thread(
            target=self._run_ids,
            daemon=True,
        )
        self._ids_thread.start()
        log.info("IDS Simulator started (target=%s)", self.rest_url)

    def _run_ids(self) -> None:
        """Run IDS simulator loop."""
        try:
            self._ids_sim.start(interval=3.0)
            while self._ids_running:
                import time
                time.sleep(0.5)
        except Exception as exc:
            log.error("IDS simulator error: %s", exc)

    def start(self) -> None:
        """Start all simulators."""
        log.info("=" * 60)
        log.info("ULPF Simulator Runner starting...")
        log.info("=" * 60)
        log.info("Configuration:")
        log.info("  REST URL: %s", self.rest_url)
        log.info("  Syslog: %s:%s", self.syslog_host, self.syslog_port)
        log.info("=" * 60)

        self._running = True

        try:
            self._init_firewall_simulator()
            log.info("-" * 40)

            self._init_router_simulator()
            log.info("-" * 40)

            self._init_ids_simulator()
            log.info("-" * 40)

            log.info("=" * 60)
            log.info("ULPF Simulator Runner started successfully!")
            log.info("Simulators running:")
            log.info("  - Firewall: Syslog UDP -> %s:%s", self.syslog_host, self.syslog_port)
            log.info("  - Router: REST API -> %s", self.rest_url)
            log.info("  - IDS: REST API -> %s", self.rest_url)
            log.info("=" * 60)
            log.info("Press Ctrl+C to stop...")

        except Exception as exc:
            log.error("Simulator startup failed: %s", exc)
            self.stop()
            raise

    def stop(self) -> None:
        """Stop all simulators gracefully."""
        if not self._running:
            return

        log.info("=" * 60)
        log.info("ULPF Simulator Runner shutting down...")
        log.info("=" * 60)

        self._firewall_running = False
        if self._firewall_sim:
            log.info("Stopping Firewall Simulator...")
            try:
                self._firewall_sim.stop()
                log.info("Firewall Simulator stopped")
            except Exception as exc:
                log.warning("Error stopping Firewall Simulator: %s", exc)

        self._router_running = False
        if self._router_sim:
            log.info("Stopping Router Simulator...")
            try:
                self._router_sim.stop()
                log.info("Router Simulator stopped")
            except Exception as exc:
                log.warning("Error stopping Router Simulator: %s", exc)

        self._ids_running = False
        if self._ids_sim:
            log.info("Stopping IDS Simulator...")
            try:
                self._ids_sim.stop()
                log.info("IDS Simulator stopped")
            except Exception as exc:
                log.warning("Error stopping IDS Simulator: %s", exc)

        self._running = False
        log.info("=" * 60)
        log.info("ULPF Simulator Runner stopped")
        log.info("=" * 60)

    def is_running(self) -> bool:
        """Check if the simulator runner is running."""
        return self._running


_runner: SimulatorRunner | None = None


def _signal_handler(signum: int, frame: Any) -> None:
    """Handle shutdown signals."""
    log.info("Received signal %d, initiating shutdown...", signum)
    if _runner:
        _runner.stop()
    sys.exit(0)


def main() -> int:
    """Main entry point for the simulator runner."""
    configure_root()

    global _runner

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    settings = get_settings()

    rest_url = f"http://127.0.0.1:{settings.ingestion.rest_ingest_port}/api/v1/ingest"
    syslog_host = "127.0.0.1"
    syslog_port = settings.ingestion.syslog_udp_port

    _runner = SimulatorRunner(
        rest_url=rest_url,
        syslog_host=syslog_host,
        syslog_port=syslog_port,
    )

    try:
        _runner.start()

        while _runner.is_running():
            try:
                import time
                time.sleep(1)
            except KeyboardInterrupt:
                break

    except Exception as exc:
        log.error("Simulator runner error: %s", exc)
        return 1
    finally:
        if _runner:
            _runner.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
