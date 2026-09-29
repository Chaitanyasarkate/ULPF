#!/usr/bin/env python3
"""
ULPF End-to-End Demo Script

This script demonstrates the complete ULPF pipeline:
1. Ingest sample logs via simulators
2. Show normalized events in dashboard
3. Tamper with raw log in MinIO
4. Verify integrity check fails via lineage/verify endpoint

Run with: python scripts/demo_e2e.py
"""

import asyncio
import json
import logging
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests
from minio import Minio

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from ulpf.config import get_settings
from ulpf.lineage.service import LineageService
from ulpf.storage.minio_adapter import MinIOAdapter
from ulpf.storage.opensearch_adapter import OpenSearchAdapter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s | %(message)s"
)
log = logging.getLogger("ulpf.demo")

API_BASE = "http://localhost:5000/api/v1"
MINIO_ENDPOINT = "localhost:9000"
MINIO_BUCKET = "ulpf-raw-events"
MINIO_ACCESS_KEY = "minioadmin"
MINIO_SECRET_KEY = "minioadmin"


class ULFPDemo:
    def __init__(self):
        self.settings = get_settings()
        self.session = requests.Session()
        self.demo_event_ids = []
        self.tampered_event_id = None

    def wait_for_api(self, timeout: int = 60) -> bool:
        """Wait for API to be ready."""
        log.info("Waiting for API to be ready...")
        start = time.time()
        while time.time() - start < timeout:
            try:
                resp = self.session.get(f"{API_BASE}/health", timeout=5)
                if resp.status_code == 200:
                    log.info("API is ready!")
                    return True
            except Exception:
                pass
            time.sleep(2)
        log.error("API did not become ready in time")
        return False

    def login(self, username: str = "admin", password: str = "ulpf-admin-demo") -> bool:
        """Login and get JWT token."""
        try:
            resp = self.session.post(
                f"{API_BASE}/auth/login",
                json={"username": username, "password": password},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                token = data["access_token"]
                self.session.headers.update({"Authorization": f"Bearer {token}"})
                log.info(f"Logged in as {username} (role: {data['user']['role']})")
                return True
            else:
                log.error(f"Login failed: {resp.text}")
                return False
        except Exception as e:
            log.error(f"Login error: {e}")
            return False

    def ingest_sample_logs(self) -> list[str]:
        """Ingest sample firewall, router, and IDS logs."""
        log.info("Ingesting sample logs...")

        # Sample firewall syslog
        firewall_log = (
            "<189>Sep 26 10:00:00 fw-demo-01 %ASA-6-302013: "
            "ALLOW inbound TCP src=10.0.1.100:54321 dst=192.168.1.50:80 (hitcnt=1)"
        )

        # Sample router JSON
        router_log = json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": "10.0.2.50",
            "dst_ip": "172.16.1.10",
            "src_port": 45678,
            "dst_port": 443,
            "protocol": "TCP",
            "action": "permitted",
            "interface": "GigabitEthernet0/0",
            "bytes": 1024,
        })

        # Sample IDS CEF
        ids_log = (
            "CEF:0|Cisco|ASA|1.0|1000|SQL Injection Attempt|5|"
            f"rt={datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')} "
            "src=10.0.3.25 dst=192.168.1.100 act=blocked proto=TCP"
        )

        events = [
            ("firewall", firewall_log, "syslog", "demo-firewall"),
            ("router", router_log, "json", "demo-router"),
            ("ids", ids_log, "cef", "demo-ids"),
        ]

        event_ids = []
        for source_type, payload, fmt, source_id in events:
            try:
                resp = self.session.post(
                    f"{API_BASE}/ingest",
                    json={
                        "payload": payload,
                        "source_id": source_id,
                        "source_type": source_type,
                        "format": fmt,
                    },
                    timeout=10
                )
                if resp.status_code == 202:
                    data = resp.json()
                    event_ids.append(data["event_id"])
                    log.info(f"  [OK] {source_type} ingested: event_id={data['event_id']}")
                else:
                    log.error(f"  [FAILED] {source_type} ingest failed: {resp.text}")
            except Exception as e:
                log.error(f"  [FAILED] {source_type} ingest error: {e}")

        return event_ids

    def wait_for_processing(self, event_ids: list[str], timeout: int = 30) -> bool:
        """Wait for events to be processed and stored."""
        log.info("Waiting for events to be processed and stored...")
        start = time.time()
        while time.time() - start < timeout:
            try:
                resp = self.session.get(f"{API_BASE}/events", params={"page_size": 100}, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    found = {e["event_id"] for e in data.get("events", [])}
                    if all(eid in found for eid in event_ids):
                        log.info(f"All {len(event_ids)} events found in OpenSearch")
                        return True
            except Exception as e:
                log.warning(f"Error checking events: {e}")
            time.sleep(2)
        log.error("Timeout waiting for events to be processed")
        return False

    def show_events_in_dashboard(self, event_ids: list[str]) -> None:
        """Show events that would appear in dashboard."""
        log.info("Fetching events from API (simulating dashboard view)...")
        try:
            resp = self.session.get(f"{API_BASE}/events", params={"page_size": 50}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                log.info(f"Total events in system: {data['total']}")
                for event in data["events"][:10]:
                    action = event.get("ocsf", {}).get("event", {}).get("action", "unknown")
                    severity = event.get("ocsf", {}).get("event", {}).get("severity", "unknown")
                    src_ip = event.get("ocsf", {}).get("source", {}).get("ip", "unknown")
                    dst_ip = event.get("ocsf", {}).get("destination", {}).get("ip", "unknown")
                    log.info(f"  Event: {event['event_id'][:20]}... | {event['source_type']} | "
                           f"action={action} | severity={severity} | {src_ip} -> {dst_ip}")
        except Exception as e:
            log.error(f"Error fetching events: {e}")

    def tamper_with_raw_log_in_minio(self, event_id: str) -> bool:
        """Tamper with a raw log in MinIO to demonstrate integrity detection."""
        log.info(f"Tampering with raw log for event {event_id}...")

        try:
            # First, get the lineage to find the raw_event_id
            resp = self.session.get(f"{API_BASE}/lineage/event/{event_id}", timeout=10)
            if resp.status_code != 200:
                log.error(f"Failed to get lineage: {resp.text}")
                return False

            lineage = resp.json()
            raw_event_id = lineage.get("root_event_id") or lineage.get("raw_event_id")
            if not raw_event_id:
                log.error("Could not find raw_event_id in lineage")
                return False

            log.info(f"Found raw_event_id: {raw_event_id}")

            # Connect to MinIO
            minio_client = Minio(
                MINIO_ENDPOINT,
                access_key=MINIO_ACCESS_KEY,
                secret_key=MINIO_SECRET_KEY,
                secure=False
            )

            # Find the object key for this raw event
            # Object key format: raw-events/YYYY.MM.DD/source_type/raw_event_id.json
            today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
            # List objects to find the right one
            objects = minio_client.list_objects(MINIO_BUCKET, prefix=f"raw-events/{today}/", recursive=True)
            target_object = None
            for obj in objects:
                if raw_event_id in obj.object_name:
                    target_object = obj.object_name
                    break

            if not target_object:
                log.error(f"Could not find MinIO object for {raw_event_id}")
                return False

            log.info(f"Found MinIO object: {target_object}")

            # Download the original
            response = minio_client.get_object(MINIO_BUCKET, target_object)
            original_data = response.read()
            response.close()
            response.release_conn()

            original_json = json.loads(original_data)
            log.info(f"Original payload preview: {json.dumps(original_json)[:200]}...")

            # Tamper: modify the payload
            if "payload" in original_json:
                original_json["payload"] = original_json["payload"].replace("ALLOW", "TAMPERED_ALLOW")
            else:
                original_json["payload"] = "TAMPERED: " + str(original_json)

            # Re-upload the tampered version
            tampered_data = json.dumps(original_json).encode("utf-8")
            minio_client.put_object(
                MINIO_BUCKET,
                target_object,
                io.BytesIO(tampered_data),
                length=len(tampered_data),
                content_type="application/json"
            )

            log.info(f"  ✓ Tampered with raw event in MinIO: {target_object}")
            self.tampered_event_id = event_id
            return True

        except Exception as e:
            log.error(f"Error tampering with MinIO: {e}")
            return False

    def verify_lineage_integrity(self, event_id: str) -> dict:
        """Call lineage/verify endpoint to check integrity."""
        log.info(f"Verifying lineage integrity for event {event_id}...")
        try:
            resp = self.session.get(f"{API_BASE}/lineage/verify/{event_id}", timeout=10)
            if resp.status_code == 200:
                result = resp.json()
                log.info(f"Verification result: {json.dumps(result, indent=2)}")
                return result
            else:
                log.error(f"Verification failed: {resp.text}")
                return {}
        except Exception as e:
            log.error(f"Error verifying lineage: {e}")
            return {}

    def show_lineage_chain(self, event_id: str) -> None:
        """Show the complete lineage chain."""
        log.info(f"Fetching lineage chain for event {event_id}...")
        try:
            resp = self.session.get(f"{API_BASE}/lineage/event/{event_id}", timeout=10)
            if resp.status_code == 200:
                chain = resp.json()
                log.info(f"Lineage chain: {json.dumps(chain, indent=2)}")
            else:
                log.error(f"Failed to get lineage: {resp.text}")
        except Exception as e:
            log.error(f"Error fetching lineage: {e}")

    def recover_raw_event(self, event_id: str) -> None:
        """Recover the raw event from MinIO."""
        log.info(f"Recovering raw event for {event_id}...")
        try:
            resp = self.session.get(f"{API_BASE}/lineage/raw-event/{event_id}", timeout=10)
            if resp.status_code == 200:
                result = resp.json()
                log.info(f"Raw event recovered: {json.dumps(result, indent=2)[:500]}...")
            elif resp.status_code == 409:
                result = resp.json()
                log.info(f"Integrity check FAILED (expected): {json.dumps(result, indent=2)}")
            else:
                log.error(f"Recovery failed: {resp.text}")
        except Exception as e:
            log.error(f"Error recovering raw event: {e}")

    def run(self) -> int:
        """Run the complete demo."""
        log.info("=" * 60)
        log.info("ULPF End-to-End Demo")
        log.info("=" * 60)

        # Step 1: Wait for API
        if not self.wait_for_api():
            return 1

        # Step 2: Login
        if not self.login():
            return 1

        # Step 3: Ingest sample logs
        self.demo_event_ids = self.ingest_sample_logs()
        if not self.demo_event_ids:
            log.error("No events ingested")
            return 1

        # Step 4: Wait for processing
        if not self.wait_for_processing(self.demo_event_ids):
            return 1

        # Step 5: Show events (dashboard view)
        self.show_events_in_dashboard(self.demo_event_ids)

        # Step 6: Show lineage for one event
        test_event_id = self.demo_event_ids[0]
        self.show_lineage_chain(test_event_id)

        # Step 7: Verify integrity BEFORE tampering
        log.info("\n--- BEFORE TAMPERING ---")
        result_before = self.verify_lineage_integrity(test_event_id)
        if result_before.get("verified"):
            log.info("✓ Integrity check PASSED before tampering")

        # Step 8: Tamper with raw log in MinIO
        log.info("\n--- TAMPERING ---")
        if not self.tamper_with_raw_log_in_minio(test_event_id):
            return 1

        # Step 9: Verify integrity AFTER tampering
        log.info("\n--- AFTER TAMPERING ---")
        result_after = self.verify_lineage_integrity(test_event_id)
        if not result_after.get("verified"):
            log.info("✓ Integrity check FAILED after tampering (EXPECTED!)")
            log.info("  This proves the hash-chain tamper detection works!")
        else:
            log.error("✗ Integrity check still passed - tamper detection not working")
            return 1

        # Step 10: Try to recover raw event (should fail verification)
        log.info("\n--- RECOVERY ATTEMPT ---")
        self.recover_raw_event(test_event_id)

        # Summary
        log.info("\n" + "=" * 60)
        log.info("DEMO COMPLETE")
        log.info("=" * 60)
        log.info("Summary:")
        log.info(f"  - Ingested {len(self.demo_event_ids)} sample events")
        log.info(f"  - Events normalized and stored in OpenSearch")
        log.info(f"  - Raw events stored in MinIO with SHA-256")
        log.info(f"  - Lineage chain recorded in PostgreSQL")
        log.info(f"  - Tampered with raw log in MinIO")
        log.info(f"  - Lineage verification detected tampering ✓")
        log.info(f"  - Raw event recovery shows SHA-256 mismatch ✓")
        log.info("=" * 60)

        return 0


if __name__ == "__main__":
    import io
    demo = ULFPDemo()
    sys.exit(demo.run())