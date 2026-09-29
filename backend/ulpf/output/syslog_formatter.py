"""Syslog output formatter for ULPF Phase 9A.

Produces RFC 3164/5424 compliant Syslog messages.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from ulpf.output.base import BaseFormatter, OutputFormat

if TYPE_CHECKING:
    from ulpf.common.models import NormalizedEvent


def _escape_syslog_value(value: Any) -> str:
    """Escape a value for Syslog format."""
    if value is None:
        return ""
    s = str(value)
    s = s.replace("\n", " ")
    s = s.replace("\r", " ")
    s = s.replace("\t", " ")
    return s


def _calculate_syslog_priority(event: NormalizedEvent) -> int:
    """Calculate Syslog PRI value from severity and facility.

    Default facility is 10 (security/authorization).
    """
    severity_map = {
        "emergency": 0,
        "alert": 1,
        "critical": 2,
        "error": 3,
        "warning": 4,
        "notice": 5,
        "informational": 6,
        "debug": 7,
        "low": 4,
        "medium": 3,
        "high": 2,
        "unknown": 6,
    }

    severity_str = "informational"
    if event.ocsf and "event" in event.ocsf:
        severity_str = str(event.ocsf.get("event", {}).get("severity", "")).lower()
    elif event.parsed_fields:
        severity_str = str(event.parsed_fields.get("severity", "")).lower()

    severity = severity_map.get(severity_str, 6)
    facility = 10

    return (facility * 8) + severity


class SyslogFormatter(BaseFormatter):
    """Formats normalized events as Syslog (RFC 3164/5424).

    Produces a structured Syslog message with key=value pairs.
    """

    formatter_id = "syslog_formatter_v1"
    formatter_name = "Syslog Formatter v1"
    formatter_version = "1.0.0"
    output_format = OutputFormat.SYSLOG
    description = "Formats events as RFC 3164/5424 compliant Syslog"

    def format(self, event: NormalizedEvent) -> str:
        """Format a normalized event as Syslog.

        Args:
            event: The normalized event to format.

        Returns:
            Syslog formatted string.
        """
        priority = _calculate_syslog_priority(event)

        timestamp = event.event_timestamp
        if not timestamp:
            timestamp = event.ingestion_timestamp

        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                timestamp = dt.strftime("%b %d %H:%M:%S")
            except (ValueError, AttributeError):
                timestamp = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        else:
            timestamp = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")

        hostname = self._get_hostname(event)
        tag = self._get_tag(event)
        msg = self._build_message(event)

        return f"<{priority}>{timestamp} {hostname} {tag}: {msg}"

    def _get_hostname(self, event: NormalizedEvent) -> str:
        """Get hostname from event."""
        host = self._get_ocsf_path(event, "device.name") or event.parsed_fields.get("host")
        if host:
            return _escape_syslog_value(host)
        if event.source_id:
            return _escape_syslog_value(event.source_id)
        return "ulpf"

    def _get_tag(self, event: NormalizedEvent) -> str:
        """Get Syslog tag (program name)."""
        source_type = event.source_type or "unknown"
        return _escape_syslog_value(source_type)

    def _build_message(self, event: NormalizedEvent) -> str:
        """Build Syslog message body."""
        parts: list[str] = []

        src_ip = self._get_ocsf_path(event, "source.ip") or event.parsed_fields.get("src_ip") or event.parsed_fields.get("src")
        dst_ip = self._get_ocsf_path(event, "destination.ip") or event.parsed_fields.get("dst_ip") or event.parsed_fields.get("dst")
        src_port = self._get_ocsf_path(event, "source.port") or event.parsed_fields.get("src_port")
        dst_port = self._get_ocsf_path(event, "destination.port") or event.parsed_fields.get("dst_port")
        proto = self._get_ocsf_path(event, "network.protocol") or event.parsed_fields.get("protocol") or event.parsed_fields.get("proto")
        action = self._get_ocsf_path(event, "event.action") or event.parsed_fields.get("action")

        if src_ip:
            parts.append(f"src={_escape_syslog_value(src_ip)}")
        if dst_ip:
            parts.append(f"dst={_escape_syslog_value(dst_ip)}")
        if src_port:
            parts.append(f"spt={_escape_syslog_value(src_port)}")
        if dst_port:
            parts.append(f"dpt={_escape_syslog_value(dst_port)}")
        if proto:
            parts.append(f"proto={_escape_syslog_value(proto)}")
        if action:
            parts.append(f"action={_escape_syslog_value(action)}")

        if event.parsed_fields:
            standard_keys = {"src_ip", "dst_ip", "src_port", "dst_port", "protocol", "proto", "action", "severity", "host", "src", "dst"}
            for key, value in sorted(event.parsed_fields.items()):
                if key not in standard_keys and value is not None:
                    parts.append(f"{_escape_syslog_value(key)}={_escape_syslog_value(value)}")

        parts.append(f"event_id={_escape_syslog_value(event.event_id)}")
        parts.append(f"raw_event_id={_escape_syslog_value(event.raw_event_id)}")

        return " ".join(parts)

    def _get_ocsf_path(self, event: NormalizedEvent, path: str) -> Any:
        """Get a value from OCSF dict using dot notation."""
        if not event.ocsf:
            return None
        parts = path.split(".")
        current = event.ocsf
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current if current != event.ocsf else None
