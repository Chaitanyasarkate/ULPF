"""LEEF (Log Event Extended Format) output formatter for ULPF Phase 9A.

LEEF Format:
    LEEF:1.0|Vendor|Product|Version|EventID|[Extension]

Extension key=value pairs are tab-separated.

References:
    https://www.ibm.com/docs/en/dsm?topic=event-extended-format
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ulpf.output.base import BaseFormatter, OutputFormat

if TYPE_CHECKING:
    from ulpf.common.models import NormalizedEvent


def _escape_leef_value(value: Any) -> str:
    """Escape a value for LEEF format."""
    if value is None:
        return ""
    s = str(value)
    s = s.replace("\\", "\\\\")
    s = s.replace("|", "\\|")
    s = s.replace("\t", "\\t")
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    return s


def _escape_leef_key(key: str) -> str:
    """Escape a LEEF key (same as value)."""
    return _escape_leef_value(key)


class LEEFFormatter(BaseFormatter):
    """Formats normalized events as LEEF (Log Event Extended Format).

    LEEF is a text-based format with pipe-delimited header and tab-separated
    key=value extension fields, used primarily by IBM QRadar.
    """

    formatter_id = "leef_formatter_v1"
    formatter_name = "LEEF Formatter v1"
    formatter_version = "1.0.0"
    output_format = OutputFormat.LEEF
    description = "Formats events as IBM QRadar LEEF (Log Event Extended Format)"

    def format(self, event: NormalizedEvent) -> str:
        """Format a normalized event as LEEF.

        Args:
            event: The normalized event to format.

        Returns:
            LEEF formatted string.
        """
        vendor = "ULPF"
        product = "UniversalLogPreprocessor"
        version = "1.0"
        event_id = event.event_id or "0"

        parts = [
            "LEEF:1.0",
            _escape_leef_value(vendor),
            _escape_leef_value(product),
            _escape_leef_value(version),
            _escape_leef_value(event_id),
        ]

        header = "|".join(parts)

        extensions = self._build_extensions(event)
        if extensions:
            return f"{header}\t{extensions}"
        return header

    def _build_extensions(self, event: NormalizedEvent) -> str:
        """Build LEEF extension key=value pairs (tab-separated)."""
        ext: dict[str, Any] = {}

        src_ip = self._get_ocsf_path(event, "source.ip") or event.parsed_fields.get("src_ip") or event.parsed_fields.get("src")
        if src_ip:
            ext["src"] = src_ip

        dst_ip = self._get_ocsf_path(event, "destination.ip") or event.parsed_fields.get("dst_ip") or event.parsed_fields.get("dst")
        if dst_ip:
            ext["dst"] = dst_ip

        src_port = self._get_ocsf_path(event, "source.port") or event.parsed_fields.get("src_port")
        if src_port:
            ext["srcPort"] = src_port

        dst_port = self._get_ocsf_path(event, "destination.port") or event.parsed_fields.get("dst_port")
        if dst_port:
            ext["dstPort"] = dst_port

        proto = self._get_ocsf_path(event, "network.protocol") or event.parsed_fields.get("protocol") or event.parsed_fields.get("proto")
        if proto:
            ext["proto"] = proto

        action = self._get_ocsf_path(event, "event.action") or event.parsed_fields.get("action")
        if action:
            ext["act"] = action

        severity = self._get_ocsf_path(event, "event.severity") or event.parsed_fields.get("severity")
        if severity:
            ext["severity"] = severity

        if event.event_timestamp:
            ext["rt"] = event.event_timestamp

        ext["raw_event_id"] = event.raw_event_id
        ext["source_type"] = event.source_type
        ext["format"] = event.format or "ocsf"
        ext["parser_id"] = event.parser_id

        if event.parsed_fields:
            for key, value in event.parsed_fields.items():
                if key not in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "proto", "action", "severity", "src", "dst"):
                    ext[key] = value

        ext_pairs = []
        for key, value in sorted(ext.items()):
            escaped_key = _escape_leef_key(key)
            escaped_value = _escape_leef_value(value)
            if escaped_value:
                ext_pairs.append(f"{escaped_key}={escaped_value}")

        return "\t".join(ext_pairs)

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
