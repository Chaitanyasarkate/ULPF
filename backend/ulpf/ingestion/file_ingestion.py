"""File ingestion for ULPF Phase 2."""

from __future__ import annotations

import logging
import os
from typing import TypedDict

from ulpf.common.models import SourceType
from ulpf.ingestion.base import ingest_raw
from ulpf.ingestion.kafka_publisher import KafkaPublisher
from ulpf.ingestion.metrics import IngestionMetrics
from ulpf.ingestion.sink import RawEventSink

logger = logging.getLogger("ulpf.ingestion.file")


class FileIngestionSummary(TypedDict):
    file: str
    format: str
    lines_processed: int
    errors: int


def _detect_format(file_path: str) -> str:
    """Best-effort format detection based on file extension and first bytes."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext in (".json", ".jsonl", ".ndjson"):
        return "json"
    if ext == ".cef":
        return "cef"
    if ext in (".log", ".txt"):
        return "text"
    return "text"


def _is_cef_line(line: str) -> bool:
    return line.strip().upper().startswith("CEF:")


def _is_json_line(line: str) -> bool:
    line = line.strip()
    if not line:
        return False
    return line.startswith("{") and line.endswith("}")


class FileIngestion:
    """Ingest events from local files incrementally."""

    def __init__(
        self,
        sink: RawEventSink,
        metrics: IngestionMetrics | None = None,
        kafka_publisher: KafkaPublisher | None = None,
    ) -> None:
        self.sink = sink
        self.metrics = metrics or sink.metrics
        self.kafka_publisher = kafka_publisher

    def ingest_file(
        self,
        file_path: str,
        source_id: str = "",
        source_type: str = SourceType.UNKNOWN.value,
        fmt: str | None = None,
        ) -> FileIngestionSummary:
        """Ingest a file line-by-line and store events in the sink.

        Args:
            file_path: Path to the file to ingest.
            source_id: Source identifier for all events in this file.
            source_type: Logical source type.
            fmt: Format override. Auto-detected from extension if omitted.

        Returns:
            Summary dict with lines_processed and errors.
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Ingestion target not found: {file_path}")

        fmt = fmt or _detect_format(file_path)
        summary: FileIngestionSummary = {"file": file_path, "format": fmt, "lines_processed": 0, "errors": 0}

        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n\r")
                if not line.strip():
                    continue
                try:
                    if fmt == "json" and _is_json_line(line) or fmt == "cef" and _is_cef_line(line):
                        payload = line
                    else:
                        payload = line

                    envelope = ingest_raw(
                        payload=payload,
                        source_id=source_id,
                        source_type=source_type,
                        fmt=fmt,
                        sink=self.sink,
                        method="file",
                    )
                    self.sink.mark_success(envelope)
                    if self.kafka_publisher is not None:
                        self.kafka_publisher.publish(envelope)
                    summary["lines_processed"] += 1
                except Exception:  # noqa: BLE001
                    logger.warning("Failed to ingest line from %s", file_path)
                    summary["errors"] += 1

        return summary
