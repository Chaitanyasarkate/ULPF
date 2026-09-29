"""Unit tests for ULPF Phase 1 ingestion layer."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from ulpf.common.hashing import sha256_str
from ulpf.common.models import EventEnvelope, ProcessingStatus
from ulpf.ingestion.base import ingest_raw
from ulpf.ingestion.file_ingestion import FileIngestion
from ulpf.ingestion.metrics import IngestionMetrics
from ulpf.ingestion.rest import create_app
from ulpf.ingestion.sink import RawEventSink


class MockKafkaPublisher:
    """Mock Kafka publisher for unit tests."""
    
    def __init__(self):
        self.producer = None
    
    def publish(self, envelope):
        return True
    
    def close(self):
        pass


@pytest.fixture()
def metrics():
    return IngestionMetrics()


@pytest.fixture()
def sink(metrics):
    return RawEventSink(metrics=metrics)


class TestIngestRaw:
    def test_creates_envelope_with_ids(self, sink):
        env = ingest_raw("test payload", source_id="fw-1", source_type="firewall", fmt="syslog", sink=sink)
        assert env.raw.raw_event_id
        assert env.raw_event_id == env.raw.raw_event_id
        assert env.raw.payload == "test payload"
        assert env.processing_status == ProcessingStatus.RECEIVED.value

    def test_sets_sha256(self, sink):
        env = ingest_raw("hello world", source_id="r-1", source_type="router", fmt="json", sink=sink)
        assert env.sha256 == sha256_str("hello world")

    def test_preserves_original_payload(self, sink):
        payload = "src=10.0.0.15 dst=192.168.1.1 sport=1234 dport=80 proto=TCP"
        env = ingest_raw(payload, source_id="fw-1", source_type="firewall", fmt="syslog", sink=sink)
        assert env.raw.payload == payload

    def test_unique_raw_event_ids(self, sink):
        env1 = ingest_raw("a", source_id="s1", sink=sink)
        env2 = ingest_raw("b", source_id="s2", sink=sink)
        assert env1.raw_event_id != env2.raw_event_id

    def test_metrics_updated(self, sink):
        ingest_raw("x", source_id="s1", source_type="firewall", fmt="syslog", sink=sink, method="test")
        snap = sink.metrics.snapshot()
        assert snap["total_received"] == 1
        assert snap["by_source"]["s1"] == 1
        assert snap["by_format"]["syslog"] == 1
        assert snap["by_method"]["test"] == 1


class TestRawEventSink:
    def test_store_returns_envelope(self, sink):
        env = EventEnvelope.from_raw("payload", source_id="s1")
        result = sink.store(env, method="unit")
        assert result is env

    def test_mark_success_sets_status(self, sink):
        env = EventEnvelope.from_raw("payload", source_id="s1")
        sink.store(env, method="unit")
        sink.mark_success(env)
        assert env.processing_status == ProcessingStatus.RAW_STORED.value

    def test_all_events_returns_copy(self, sink):
        ingest_raw("a", source_id="s1", sink=sink)
        ingest_raw("b", source_id="s2", sink=sink)
        events = sink.all_events()
        assert len(events) == 2
        assert events[0].raw_event_id
        assert events[1].raw_event_id

    def test_clear_removes_events(self, sink):
        ingest_raw("a", source_id="s1", sink=sink)
        sink.clear()
        assert sink.all_events() == []


class TestRestAPI:
    def test_health_endpoint(self):
        app = create_app()
        client = app.test_client()
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"

    def test_ingest_valid_payload(self):
        app = create_app()
        client = app.test_client()
        body = {"payload": "syslog line", "source_id": "fw-1", "source_type": "firewall", "format": "syslog"}
        resp = client.post("/api/v1/ingest", json=body)
        assert resp.status_code == 202
        data = resp.get_json()
        assert data["status"] == "accepted"
        assert data["raw_event_id"]
        assert data["sha256"]

    def test_ingest_missing_payload(self):
        app = create_app()
        client = app.test_client()
        resp = client.post("/api/v1/ingest", json={"source_id": "x"})
        assert resp.status_code == 400

    def test_ingest_malformed_json(self):
        app = create_app()
        client = app.test_client()
        resp = client.post("/api/v1/ingest", data="not-json", content_type="application/json")
        assert resp.status_code == 400

    def test_ingest_non_string_payload(self):
        app = create_app()
        client = app.test_client()
        resp = client.post("/api/v1/ingest", json={"payload": 123})
        assert resp.status_code == 400

    def test_metrics_endpoint(self):
        app = create_app()
        client = app.test_client()
        client.post("/api/v1/ingest", json={"payload": "test"})
        resp = client.get("/metrics")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total_received"] >= 1


class TestSyslogListener:
    def test_parse_simple_syslog(self):
        from ulpf.ingestion.syslog import _parse_syslog_line
        result = _parse_syslog_line("<13>Jul 15 2026 10:23:41 fw01 %ASA-6-302013: Built")
        assert result["host"] == "fw01"
        assert result["message"] == "%ASA-6-302013: Built"

    def test_parse_fallback_for_non_syslog(self):
        from ulpf.ingestion.syslog import _parse_syslog_line
        result = _parse_syslog_line("just a plain line")
        assert result["message"] == "just a plain line"


class TestFileIngestion:
    def test_ingest_json_lines(self, tmp_path, sink):
        p = tmp_path / "sample.jsonl"
        p.write_text(json.dumps({"event": 1}) + "\n" + json.dumps({"event": 2}) + "\n")
        ing = FileIngestion(sink=sink)
        result = ing.ingest_file(str(p), source_id="file-1", source_type="server")
        assert result["lines_processed"] == 2
        assert result["errors"] == 0

    def test_ingest_plain_text(self, tmp_path, sink):
        p = tmp_path / "sample.log"
        p.write_text("line one\nline two\n")
        ing = FileIngestion(sink=sink)
        result = ing.ingest_file(str(p), source_id="file-1")
        assert result["lines_processed"] == 2

    def test_ingest_cef(self, tmp_path, sink):
        p = tmp_path / "sample.cef"
        p.write_text("CEF:0|Vendor|Product|1.0|1000|Signature|1|src=1.2.3.4\n")
        ing = FileIngestion(sink=sink)
        result = ing.ingest_file(str(p), source_id="ids-1", source_type="ids")
        assert result["lines_processed"] == 1

    def test_ingest_missing_file_raises(self, sink):
        ing = FileIngestion(sink=sink)
        with pytest.raises(FileNotFoundError):
            ing.ingest_file("/nonexistent/path.log")
