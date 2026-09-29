"""CSV output formatter for ULPF Phase 9A.

Produces RFC 4180 compliant CSV with proper quoting and escaping.
"""

from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING, Any, ClassVar

from ulpf.output.base import BaseFormatter, OutputFormat

if TYPE_CHECKING:
    from ulpf.common.models import NormalizedEvent


class CSVFormatter(BaseFormatter):
    """Formats normalized events as RFC 4180 compliant CSV.

    CSV includes standardized fields plus any extra parsed fields.
    Unknown fields are preserved in dynamic columns.
    """

    formatter_id = "csv_formatter_v1"
    formatter_name = "CSV Formatter v1"
    formatter_version = "1.0.0"
    output_format = OutputFormat.CSV
    description = "Formats events as RFC 4180 compliant CSV"

    _standard_fields: ClassVar[list[str]] = [
        "event_id",
        "raw_event_id",
        "source_id",
        "source_type",
        "format",
        "parser_id",
        "parser_version",
        "schema_version",
        "event_timestamp",
        "ingestion_timestamp",
        "sha256",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "action",
        "severity",
        "host",
    ]

    def format(self, event: NormalizedEvent) -> str:
        """Format a normalized event as CSV.

        Args:
            event: The normalized event to format.

        Returns:
            RFC 4180 compliant CSV string.
        """
        row = self._build_row(event)
        headers = self._get_headers(event)

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\n")
        writer.writerow(headers)
        writer.writerow(row)

        return output.getvalue()

    def _get_headers(self, event: NormalizedEvent) -> list[str]:
        """Get CSV headers including standard and extra fields."""
        headers = list(self._standard_fields)

        if event.parsed_fields:
            extra = set(event.parsed_fields.keys()) - set(self._standard_fields)
            for field in sorted(extra):
                if field not in headers:
                    headers.append(field)

        headers.extend(["raw_payload"])

        return headers

    def _build_row(self, event: NormalizedEvent) -> list[str]:
        """Build CSV row from event data."""
        row: dict[str, str] = {}

        row["event_id"] = str(event.event_id or "")
        row["raw_event_id"] = str(event.raw_event_id or "")
        row["source_id"] = str(event.source_id or "")
        row["source_type"] = str(event.source_type or "")
        row["format"] = str(event.format or "")
        row["parser_id"] = str(event.parser_id or "")
        row["parser_version"] = str(event.parser_version or "")
        row["schema_version"] = str(event.schema_version or "")
        row["event_timestamp"] = str(event.event_timestamp or "")
        row["ingestion_timestamp"] = str(event.ingestion_timestamp or "")
        row["sha256"] = str(event.sha256 or "")

        src_ip = self._get_ocsf_path(event, "source.ip") or event.parsed_fields.get("src_ip") or event.parsed_fields.get("src", "")
        row["src_ip"] = str(src_ip or "")

        dst_ip = self._get_ocsf_path(event, "destination.ip") or event.parsed_fields.get("dst_ip") or event.parsed_fields.get("dst", "")
        row["dst_ip"] = str(dst_ip or "")

        src_port = self._get_ocsf_path(event, "source.port") or event.parsed_fields.get("src_port", "")
        row["src_port"] = str(src_port or "")

        dst_port = self._get_ocsf_path(event, "destination.port") or event.parsed_fields.get("dst_port", "")
        row["dst_port"] = str(dst_port or "")

        proto = self._get_ocsf_path(event, "network.protocol") or event.parsed_fields.get("protocol") or event.parsed_fields.get("proto", "")
        row["protocol"] = str(proto or "")

        action = self._get_ocsf_path(event, "event.action") or event.parsed_fields.get("action", "")
        row["action"] = str(action or "")

        severity = self._get_ocsf_path(event, "event.severity") or event.parsed_fields.get("severity", "")
        row["severity"] = str(severity or "")

        host = self._get_ocsf_path(event, "device.name") or event.parsed_fields.get("host", "")
        row["host"] = str(host or "")

        if event.parsed_fields:
            for field, value in event.parsed_fields.items():
                if field not in self._standard_fields:
                    row[field] = str(value) if value is not None else ""

        row["raw_payload"] = event.raw_payload or ""

        headers = self._get_headers(event)
        return [row.get(h, "") for h in headers]

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
