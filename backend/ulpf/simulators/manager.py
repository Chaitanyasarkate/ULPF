"""Global simulator manager for ULPF.

Manages simulator subprocesses so the API server can start/stop them
on demand without restarting the whole stack.

Run simulators as child processes of the API server so they can be
controlled via REST endpoints.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
from typing import Any

from ulpf.common.logging import get_logger

log = get_logger("ulpf.simulators.manager")


class SimulatorManager:
    """Manages simulator subprocess lifecycle."""

    _instance: "SimulatorManager | None" = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self._processes: dict[str, subprocess.Popen | None] = {
            "firewall": None,
            "router": None,
            "ids": None,
        }
        self._running: dict[str, bool] = {
            "firewall": False,
            "router": False,
            "ids": False,
        }

    @classmethod
    def get_instance(cls) -> "SimulatorManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = SimulatorManager()
        return cls._instance

    def _python_executable(self) -> str:
        return sys.executable

    def _backend_root(self) -> str:
        # backend/ is two levels up from this file
        here = os.path.dirname(os.path.abspath(__file__))
        return os.path.dirname(here)  # backend/

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = self._backend_root() + os.pathsep + env.get("PYTHONPATH", "")
        return env

    def _clear_event_store(self) -> None:
        """Clear all stored events, drift events, and anomalies so each monitoring cycle starts fresh."""
        try:
            import asyncio

            async def _clear():
                # Clear OpenSearch events
                from ulpf.storage.opensearch_adapter import OpenSearchAdapter
                adapter = OpenSearchAdapter()
                try:
                    cleared = adapter.clear_all_events()
                    log.info("Cleared %d OpenSearch indices for new monitoring cycle", cleared)
                finally:
                    adapter.close()

                # Clear schema drift events (sync psycopg2)
                try:
                    from ulpf.schema.repository import SchemaRepository
                    schema_repo = SchemaRepository()
                    drift_cleared = schema_repo.clear_drift_events()
                    log.info("Cleared %d schema drift events for new monitoring cycle", drift_cleared)
                except Exception as exc:
                    log.warning("Failed to clear drift events: %s", exc)

                # Clear anomalies (async asyncpg)
                try:
                    from ulpf.analytics.repository import AnomalyRepository
                    anomaly_repo = AnomalyRepository()
                    anomaly_cleared = await anomaly_repo.clear_all_anomalies()
                    log.info("Cleared %d anomalies for new monitoring cycle", anomaly_cleared)
                except Exception as exc:
                    log.warning("Failed to clear anomalies: %s", exc)

            asyncio.run(_clear())

            # Reset Kafka consumer group offsets to latest so the orchestrator
            # does not replay old messages that would re-populate the stores.
            self._reset_kafka_offsets()

            # Restart orchestrator so it picks up new offsets
            self._restart_orchestrator()
        except Exception as exc:
            log.warning("Failed to clear event store: %s", exc)

    def _reset_kafka_offsets(self) -> None:
        """Reset all ULPF consumer groups to the latest offset.

        Uses the kafka-consumer-groups tool inside the Kafka container
        so the orchestrator does not replay old messages after a reset.
        """
        import subprocess

        group_ids = [
            "ulpf-processing-raw-storage",
            "ulpf-processing",
            "ulpf-processing-normalized-storage",
        ]

        for group_id in group_ids:
            try:
                cmd = [
                    "docker", "exec", "ulpf_kafka",
                    "/usr/bin/kafka-consumer-groups",
                    "--bootstrap-server", "localhost:9092",
                    "--group", group_id,
                    "--reset-offsets", "--to-latest",
                    "--execute",
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0:
                    log.info("Reset Kafka consumer group %s to latest", group_id)
                else:
                    log.warning(
                        "Failed to reset consumer group %s: %s",
                        group_id, result.stderr.strip() or result.stdout.strip(),
                    )
            except Exception as exc:
                log.warning("Kafka reset error for %s: %s", group_id, exc)

    def _restart_orchestrator(self) -> None:
        """Restart the orchestrator process so it picks up new Kafka offsets."""
        import subprocess

        # Kill existing orchestrator
        try:
            subprocess.run(
                ["tasklist", "/FI", "imagename eq python.exe", "/FO", "table"],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass

        # Use wmic to find and kill orchestrator processes
        try:
            find_cmd = (
                'Get-CimInstance Win32_Process | '
                'Where-Object { $_.CommandLine -like "*ulpf.orchestrator*" } | '
                'Select-Object ProcessId'
            )
            result = subprocess.run(
                ["powershell", "-Command", find_cmd],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if line.isdigit():
                    pid = int(line)
                    try:
                        subprocess.run(
                            ["taskkill", "/PID", str(pid), "/F"],
                            capture_output=True, timeout=5,
                        )
                        log.info("Killed orchestrator PID=%s", pid)
                    except Exception:
                        pass
        except Exception as exc:
            log.warning("Failed to kill orchestrator: %s", exc)

        # Restart orchestrator
        try:
            backend_root = self._backend_root()
            subprocess.Popen(
                [self._python_executable(), "-m", "ulpf.orchestrator"],
                env=self._env(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            log.info("Restarted orchestrator")
        except Exception as exc:
            log.warning("Failed to restart orchestrator: %s", exc)

    def start_all(self) -> dict[str, Any]:
        """Start all three simulators and reset event counts."""
        self._clear_event_store()
        self.start("firewall")
        self.start("router")
        self.start("ids")
        return self.status()

    def stop_all(self) -> dict[str, Any]:
        """Stop all running simulators."""
        for name in ("firewall", "router", "ids"):
            self.stop(name)
        return self.status()

    def start(self, name: str) -> dict[str, Any]:
        """Start a single simulator by name."""
        name = name.lower()
        if name not in self._running:
            return {"error": f"Unknown simulator: {name}", "running": False}

        if self._running[name]:
            return {"message": f"{name} already running", "running": True}

        try:
            if name == "firewall":
                code = (
                    "import time, sys; "
                    "sys.path.insert(0, 'D:/Log/backend'); "
                    "from ulpf.simulators.firewall import FirewallSimulator; "
                    "sim = FirewallSimulator(target_host='127.0.0.1', target_port=5514); "
                    "sim.start(interval=1.0); "
                    "while True: time.sleep(10)"
                )
            elif name == "router":
                code = (
                    "import time, sys; "
                    "sys.path.insert(0, 'D:/Log/backend'); "
                    "from ulpf.simulators.router import RouterSimulator; "
                    "sim = RouterSimulator(rest_url='http://127.0.0.1:8000/api/v1/ingest'); "
                    "sim.start(interval=2.0); "
                    "while True: time.sleep(10)"
                )
            elif name == "ids":
                code = (
                    "import time, sys; "
                    "sys.path.insert(0, 'D:/Log/backend'); "
                    "from ulpf.simulators.ids import IDSSimulator; "
                    "sim = IDSSimulator(rest_url='http://127.0.0.1:8000/api/v1/ingest'); "
                    "sim.start(interval=3.0); "
                    "while True: time.sleep(10)"
                )

            proc = subprocess.Popen(
                [self._python_executable(), "-c", code],
                env=self._env(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._processes[name] = proc
            self._running[name] = True
            log.info("Started %s simulator (PID=%s)", name, proc.pid)
            return {"message": f"{name} simulator started", "running": True, "pid": proc.pid}
        except Exception as exc:
            log.error("Failed to start %s simulator: %s", name, exc)
            return {"error": str(exc), "running": False}

    def stop(self, name: str) -> dict[str, Any]:
        """Stop a single simulator by name."""
        name = name.lower()
        if name not in self._running:
            return {"error": f"Unknown simulator: {name}", "running": False}

        if not self._running[name]:
            return {"message": f"{name} not running", "running": False}

        proc = self._processes.get(name)
        if proc and proc.poll() is None:
            try:
                proc.send_signal(signal.CTRL_BREAK_EVENT)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        self._processes[name] = None
        self._running[name] = False
        log.info("Stopped %s simulator", name)
        return {"message": f"{name} simulator stopped", "running": False}

    def status(self) -> dict[str, Any]:
        """Return status of all simulators."""
        result: dict[str, Any] = {}
        for name in ("firewall", "router", "ids"):
            proc = self._processes.get(name)
            running = False
            pid = None
            if proc is not None:
                if proc.poll() is None:
                    running = True
                    pid = proc.pid
                else:
                    # Process exited
                    self._processes[name] = None
                    self._running[name] = False
            result[name] = {
                "running": running or self._running[name],
                "pid": pid,
            }
        result["any_running"] = any(v["running"] for v in result.values() if isinstance(v, dict))
        return result

    def shutdown(self) -> None:
        """Stop all simulators."""
        self.stop_all()


def get_simulator_manager() -> SimulatorManager:
    return SimulatorManager.get_instance()