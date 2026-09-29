"""CEF (Common Event Format) output formatter for ULPF Phase 9A.

CEF Format:
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|[Extension]

References:
    https://community.microfocus.com/cyberres/arcsight/f/hpe-arctouch-arcsight-user-discussions/109820
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ulpf.output.base import BaseFormatter, OutputFormat

if TYPE_CHECKING:
    from ulpf.common.models import NormalizedEvent


def _escape_cef_value(value: Any) -> str:
    """Escape a value for CEF format (backslash escape)."""
    if value is None:
        return ""
    s = str(value)
    s = s.replace("\\", "\\\\")
    s = s.replace("=", "\\=")
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\t", "\\t")
    return s


def _get_cef_severity(event: NormalizedEvent) -> str:
    """Map OCSF severity to CEF severity (0-10)."""
    severity_map = {
        "informational": "5",
        "low": "6",
        "medium": "7",
        "high": "8",
        "critical": "10",
        "unknown": "5",
    }
    ocsf_severity = ""
    if event.ocsf and "event" in event.ocsf:
        ocsf_severity = str(event.ocsf.get("event", {}).get("severity", "")).lower()
    elif event.parsed_fields:
        ocsf_severity = str(event.parsed_fields.get("severity", "")).lower()

    return severity_map.get(ocsf_severity, "5")


def _get_cef_action(event: NormalizedEvent) -> str:
    """Get action for CEF extension."""
    if event.ocsf and "event" in event.ocsf:
        return str(event.ocsf.get("event", {}).get("action", ""))
    return str(event.parsed_fields.get("action", ""))


class CEFFormatter(BaseFormatter):
    """Formats normalized events as CEF (Common Event Format).

    CEF is a text-based format with pipe-delimited header and key=value
    extension fields.
    """

    formatter_id = "cef_formatter_v1"
    formatter_name = "CEF Formatter v1"
    formatter_version = "1.0.0"
    output_format = OutputFormat.CEF
    description = "Formats events as HP ArcSight CEF (Common Event Format)"

    def format(self, event: NormalizedEvent) -> str:
        """Format a normalized event as CEF.

        Args:
            event: The normalized event to format.

        Returns:
            CEF formatted string.
        """
        vendor = "ULPF"
        product = "UniversalLogPreprocessor"
        version = "1.0"

        signature_id = event.event_id or "0"
        name = _get_cef_action(event) or "Network Event"
        severity = _get_cef_severity(event)

        parts = [
            "CEF:0",
            _escape_cef_value(vendor),
            _escape_cef_value(product),
            _escape_cef_value(version),
            _escape_cef_value(signature_id),
            _escape_cef_value(name),
            severity,
        ]

        header = "|".join(parts)

        extensions = self._build_extensions(event)
        if extensions:
            return f"{header}|{extensions}"
        return header

    def _build_extensions(self, event: NormalizedEvent) -> str:
        """Build CEF extension key=value pairs."""
        ext: dict[str, Any] = {}

        src_ip = self._get_ocsf_path(event, "source.ip") or event.parsed_fields.get("src_ip") or event.parsed_fields.get("src")
        if src_ip:
            ext["src"] = src_ip

        dst_ip = self._get_ocsf_path(event, "destination.ip") or event.parsed_fields.get("dst_ip") or event.parsed_fields.get("dst")
        if dst_ip:
            ext["dst"] = dst_ip

        src_port = self._get_ocsf_path(event, "source.port") or event.parsed_fields.get("src_port")
        if src_port:
            ext["spt"] = src_port

        dst_port = self._get_ocsf_path(event, "destination.port") or event.parsed_fields.get("dst_port")
        if dst_port:
            ext["dpt"] = dst_port

        proto = self._get_ocsf_path(event, "network.protocol") or event.parsed_fields.get("protocol") or event.parsed_fields.get("proto")
        if proto:
            ext["proto"] = proto

        rt = event.event_timestamp or event.ingestion_timestamp
        if rt:
            ext["rt"] = rt

        if event.parsed_fields:
            for key, value in event.parsed_fields.items():
                if key not in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "proto", "action", "severity"):
                    ext[key] = value

        ext_pairs = []
        for key, value in sorted(ext.items()):
            escaped_value = _escape_cef_value(value)
            if escaped_value:
                ext_pairs.append(f"{key}={escaped_value}")

        return " ".join(ext_pairs)

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
