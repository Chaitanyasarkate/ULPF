"""Real ingestion metrics for ULPF Phase 1."""

from __future__ import annotations

import threading
from collections import defaultdict
from datetime import datetime, timezone


class IngestionMetrics:
    """Thread-safe ingestion metrics collector."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_received: int = 0
        self.successful: int = 0
        self.failed: int = 0
        self.by_source: dict[str, int] = defaultdict(int)
        self.by_format: dict[str, int] = defaultdict(int)
        self.by_method: dict[str, int] = defaultdict(int)
        self.last_received: str | None = None

    def record_received(self, source_id: str, fmt: str, method: str) -> None:
        with self._lock:
            self.total_received += 1
            self.by_source[source_id or "unknown"] += 1
            self.by_format[fmt or "unknown"] += 1
            self.by_method[method or "unknown"] += 1
            self.last_received = datetime.now(timezone.utc).isoformat()

    def record_success(self) -> None:
        with self._lock:
            self.successful += 1

    def record_failure(self) -> None:
        with self._lock:
            self.failed += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "total_received": self.total_received,
                "successful": self.successful,
                "failed": self.failed,
                "by_source": dict(self.by_source),
                "by_format": dict(self.by_format),
                "by_method": dict(self.by_method),
                "last_received": self.last_received,
            }
