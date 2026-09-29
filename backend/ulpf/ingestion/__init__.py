"""ULPF ingestion package.

Exports core ingestion primitives for Phase 1:
- base ingestion helpers
- syslog listener
- REST API
- file ingestion
- metrics
- raw event sink
- kafka publisher
"""

from __future__ import annotations

from ulpf.ingestion.base import ingest_raw
from ulpf.ingestion.file_ingestion import FileIngestion
from ulpf.ingestion.kafka_publisher import KafkaPublisher
from ulpf.ingestion.metrics import IngestionMetrics
from ulpf.ingestion.rest import create_app
from ulpf.ingestion.sink import RawEventSink
from ulpf.ingestion.syslog import SyslogListener

__all__ = [
    "FileIngestion",
    "IngestionMetrics",
    "KafkaPublisher",
    "RawEventSink",
    "SyslogListener",
    "create_app",
    "ingest_raw",
]
