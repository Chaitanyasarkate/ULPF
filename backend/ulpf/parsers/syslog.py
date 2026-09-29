"""Syslog parser for ULPF Phase 3."""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from ulpf.common.models import EventEnvelope, ParsedEvent, SourceType
from ulpf.parsers.base import BaseParser

logger = logging.getLogger("ulpf.parsers.syslog")

_SYSLOG_PATTERN = re.compile(
    r"^(?P<priority><(?P<priority_val>\d+)>)?\s*"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<message>.+)$"
)

_ACTION_MAP = {
    "ALLOW": "allow",
    "DENY": "deny",
    "DROP": "drop",
    "ACCEPT": "accept",
    "BUILT": "built",
}

_PROTOCOLS = {"TCP", "UDP", "ICMP", "IP"}


def _parse_facility_severity(priority_str: str | None) -> dict[str, int | None]:
    if not priority_str:
        return {"facility": None, "severity": None}
    try:
        pri = int(priority_str)
        return {"facility": pri // 8, "severity": pri % 8}
    except ValueError:
        return {"facility": None, "severity": None}


def _parse_syslog_line(line: str) -> dict[str, Any]:
    line = line.strip()
    if not line:
        return {}

    m = _SYSLOG_PATTERN.match(line)
    if not m:
        return {"message": line}

    data = m.groupdict()
    ts_str = data.get("timestamp", "")
    event_timestamp = None
    if ts_str:
        try:
            now = datetime.now(timezone.utc)
            parsed = datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(year=now.year, tzinfo=timezone.utc)
            event_timestamp = parsed.isoformat()
        except ValueError:
            pass

    pri = data.get("priority_val")
    fac_sev = _parse_facility_severity(pri)

    message = data.get("message", line)
    action = None
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    protocol = None

    for token in message.split():
        if token.startswith("src="):
            val = token[4:]
            if ":" in val:
                ip, port = val.split(":", 1)
                src_ip = ip
                try:
                    src_port = int(port)
                except ValueError:
                    src_port = None
            else:
                src_ip = val
        elif token.startswith("dst="):
            val = token[4:]
            if ":" in val:
                ip, port = val.split(":", 1)
                dst_ip = ip
                try:
                    dst_port = int(port)
                except ValueError:
                    dst_port = None
            else:
                dst_ip = val
        elif token.startswith("proto="):
            protocol = token[6:]
        elif token.startswith("action="):
            action = token[7:]

    # Fallback: parse simple "IP:port -> IP:port" format
    if not src_ip or not dst_ip:
        arrow_match = re.search(
            r"(\d+\.\d+\.\d+\.\d+)(?::(\d+))?\s*->\s*"
            r"(\d+\.\d+\.\d+\.\d+)(?::(\d+))?",
            message,
        )
        if arrow_match:
            if not src_ip:
                src_ip = arrow_match.group(1)
            if not src_port and arrow_match.group(2):
                try:
                    src_port = int(arrow_match.group(2))
                except ValueError:
                    pass
            if not dst_ip:
                dst_ip = arrow_match.group(3)
            if not dst_port and arrow_match.group(4):
                try:
                    dst_port = int(arrow_match.group(4))
                except ValueError:
                    pass

    for key, mapped in _ACTION_MAP.items():
        if key in message.upper() and action is None:
            action = mapped
            break

    if protocol is None:
        for proto in _PROTOCOLS:
            if f" {proto}" in message.upper():
                protocol = proto
                break

    return {
        "timestamp": event_timestamp,
        "host": data.get("host", ""),
        "message": message,
        "priority": pri,
        "facility": fac_sev["facility"],
        "severity": fac_sev["severity"],
        "action": action,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
    }


class FirewallSyslogParser(BaseParser):
    """Parser for Firewall Syslog events."""

    parser_id = "firewall_syslog_v1"
    parser_name = "Firewall Syslog Parser v1"
    source_type = SourceType.FIREWALL.value
    format = "syslog"
    parser_version = "1.0.0"
    description = "Parses Cisco ASA-style firewall syslog events"

    def parse(self, envelope: EventEnvelope) -> ParsedEvent:
        fields = _parse_syslog_line(envelope.raw.payload)
        # Reuse existing parsed event_id if available (from ingestion)
        existing_event_id = envelope.parsed.event_id if envelope.parsed else None
        return ParsedEvent(
            event_id=existing_event_id or str(uuid.uuid4()),
            raw_event_id=envelope.raw_event_id,
            source_id=envelope.raw.source_id,
            source_type=envelope.raw.source_type,
            format=envelope.raw.format,
            parser_id=self.parser_id,
            parser_version=self.parser_version,
            extracted={k: v for k, v in fields.items() if v is not None},
            event_timestamp=fields.get("timestamp"),
        )
