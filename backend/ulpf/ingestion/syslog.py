"""Syslog ingestion listener for ULPF Phase 2."""

from __future__ import annotations

import logging
import re
import socketserver
import threading
from datetime import datetime, timezone

from ulpf.common.hashing import sha256_str
from ulpf.common.models import SourceType
from ulpf.ingestion.base import ingest_raw
from ulpf.ingestion.kafka_publisher import KafkaPublisher
from ulpf.ingestion.sink import RawEventSink

logger = logging.getLogger("ulpf.ingestion.syslog")

_SYSLOG_PATTERN = re.compile(
    r"^(?P<priority><\d+>)?\s*"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<message>.+)$"
)


def _parse_syslog_line(line: str) -> dict:
    """Parse a basic RFC 3164 syslog line. Return dict with parsed fields."""
    line = line.strip()
    if not line:
        return {}

    m = _SYSLOG_PATTERN.match(line)
    if not m:
        return {"message": line}

    data = m.groupdict()
    # Try to parse timestamp into ISO format (best effort).
    ts_str = data.get("timestamp", "")
    event_timestamp = None
    if ts_str:
        try:
            now = datetime.now(timezone.utc)
            parsed = datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(year=now.year, tzinfo=timezone.utc)
            event_timestamp = parsed.isoformat()
        except ValueError:
            pass

    return {
        "timestamp": event_timestamp,
        "host": data.get("host", ""),
        "message": data.get("message", line),
        "priority": data.get("priority", ""),
    }


class _SyslogUDPHandler(socketserver.BaseRequestHandler):
    """UDP syslog handler that stores events in the shared sink."""

    sink: RawEventSink = None  # type: ignore[assignment]
    source_type: str = SourceType.UNKNOWN.value
    method: str = "syslog_udp"
    kafka_publisher: KafkaPublisher | None = None

    def handle(self) -> None:
        try:
            data = self.request[0].decode("utf-8", errors="replace")
            for line in data.splitlines():
                line = line.strip()
                if not line:
                    continue
                parsed = _parse_syslog_line(line)
                host = parsed.get("host", self.client_address[0])
                envelope = ingest_raw(
                    payload=line,
                    source_id=host,
                    source_type=self.source_type,
                    fmt="syslog",
                    sink=self.sink,
                    method=self.method,
                )
                envelope.sha256 = sha256_str(line)
                self.sink.store(envelope, method=self.method)
                self.sink.mark_success(envelope)
                if self.kafka_publisher is not None:
                    self.kafka_publisher.publish(envelope)
        except Exception:
            logger.exception("UDP syslog handler error")


class _SyslogTCPHandler(socketserver.BaseRequestHandler):
    """TCP syslog handler that stores events in the shared sink."""

    sink: RawEventSink = None  # type: ignore[assignment]
    source_type: str = SourceType.UNKNOWN.value
    method: str = "syslog_tcp"
    kafka_publisher: KafkaPublisher | None = None

    def handle(self) -> None:
        try:
            stream = self.request.makefile("r", encoding="utf-8", errors="replace")
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                parsed = _parse_syslog_line(line)
                host = parsed.get("host", self.client_address[0])
                envelope = ingest_raw(
                    payload=line,
                    source_id=host,
                    source_type=self.source_type,
                    fmt="syslog",
                    sink=self.sink,
                    method=self.method,
                )
                envelope.sha256 = sha256_str(line)
                self.sink.store(envelope, method=self.method)
                self.sink.mark_success(envelope)
                if self.kafka_publisher is not None:
                    self.kafka_publisher.publish(envelope)
        except Exception:
            logger.exception("TCP syslog handler error")


class SyslogListener:
    """Manages UDP and/or TCP syslog listeners."""

    def __init__(
        self,
        sink: RawEventSink,
        udp_port: int = 5514,
        tcp_port: int = 514,
        host: str = "0.0.0.0",
        source_type: str = SourceType.UNKNOWN.value,
        kafka_publisher: KafkaPublisher | None = None,
    ) -> None:
        self.sink = sink
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.host = host
        self.source_type = source_type
        self.kafka_publisher = kafka_publisher
        self._servers: list[socketserver.ThreadingTCPServer | socketserver.ThreadingUDPServer] = []
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        if self.udp_port > 0:
            udp_server = socketserver.ThreadingUDPServer(
                (self.host, self.udp_port), _SyslogUDPHandler
            )
            _SyslogUDPHandler.sink = self.sink
            _SyslogUDPHandler.source_type = self.source_type
            _SyslogUDPHandler.method = "syslog_udp"
            _SyslogUDPHandler.kafka_publisher = self.kafka_publisher
            t = threading.Thread(target=udp_server.serve_forever, daemon=True)
            t.start()
            self._servers.append(udp_server)
            self._threads.append(t)
            logger.info("Syslog UDP listener started on %s:%s", self.host, self.udp_port)

        if self.tcp_port > 0:
            tcp_server = socketserver.ThreadingTCPServer(
                (self.host, self.tcp_port), _SyslogTCPHandler
            )
            _SyslogTCPHandler.sink = self.sink
            _SyslogTCPHandler.source_type = self.source_type
            _SyslogTCPHandler.method = "syslog_tcp"
            _SyslogTCPHandler.kafka_publisher = self.kafka_publisher
            t = threading.Thread(target=tcp_server.serve_forever, daemon=True)
            t.start()
            self._servers.append(tcp_server)
            self._threads.append(t)
            logger.info("Syslog TCP listener started on %s:%s", self.host, self.tcp_port)

    def stop(self) -> None:
        for server in self._servers:
            server.shutdown()
        for thread in self._threads:
            thread.join(timeout=5)
        logger.info("Syslog listeners stopped")
