"""Pytest configuration and shared fixtures for ULPF tests."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Make the backend package importable: backend/ulpf is the package root.
ROOT = Path(__file__).resolve().parent
BACKEND_ROOT = ROOT  # backend/
sys.path.insert(0, str(BACKEND_ROOT))

# Ensure test-only env defaults exist so tests are hermetic and do not depend
# on a developer's .env file.
os.environ.setdefault("ULPF_ENV", "test")
os.environ.setdefault("ULPF_LOG_LEVEL", "DEBUG")
os.environ.setdefault("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
os.environ.setdefault("MINIO_ROOT_USER", "minioadmin")
os.environ.setdefault("MINIO_ROOT_PASSWORD", "minioadmin")
os.environ.setdefault("POSTGRES_PASSWORD", "test")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-not-for-prod")


@pytest.fixture
def sample_envelope_dict():
    """A representative raw event payload as it would arrive on the raw-logs topic."""
    return {
        "raw": {
            "raw_event_id": "00000000-0000-4000-8000-000000000001",
            "source_id": "fw-01",
            "source_type": "firewall",
            "format": "syslog",
            "received_at": "2026-09-07T06:00:00+00:00",
            "payload": "Jul 15 2026 10:23:41 firewall1 %ASA-6-302013: Built inbound TCP connection 123456",
            "original_payload_bytes": 86,
        },
        "parsed": None,
        "normalized": None,
        "sha256": "",
        "previous_hash": "",
        "current_hash": "",
        "processing_status": "received",
        "error": None,
        "parser_id": "",
        "parser_version": "",
        "schema_version": "1.0.0",
        "drift_flags": {},
    }
