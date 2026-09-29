"""CEF parser for ULPF Phase 3."""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any

from ulpf.common.models import EventEnvelope, ParsedEvent, SourceType
from ulpf.parsers.base import BaseParser

logger = logging.getLogger("ulpf.parsers.cef")

_CEF_PATTERN = re.compile(
    r"^CEF:(?P<version>\d+)\|"
    r"(?P<device_vendor>[^|]+)\|"
    r"(?P<device_product>[^|]+)\|"
    r"(?P<device_version>[^|]+)\|"
    r"(?P<signature_id>\d+)\|"
    r"(?P<name>[^|]+)\|"
    r"(?P<severity>\d+)\|"
    r"(?P<extension>.+)$"
)


def _parse_extension(extension: str) -> dict[str, str]:
    """Parse CEF extension key=value pairs.

    CEF extension values may contain spaces when they are not escaped.
    This implementation splits on ``key=`` boundaries to handle spaces
    in values correctly.
    """
    result: dict[str, str] = {}
    if not extension:
        return result

    matches = list(re.finditer(r"(\w+)=", extension))
    for i, m in enumerate(matches):
        key = m.group(1)
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(extension)
        value = extension[start:end].strip()
        value = value.replace("\\\\", "\\").replace("\\=", "=")
        result[key] = value
    return result


def _parse_cef_line(line: str) -> dict[str, Any]:
    line = line.strip()
    if not line:
        return {}

    m = _CEF_PATTERN.match(line)
    if not m:
        return {"message": line}

    header = m.groupdict()
    extension_raw = header.pop("extension", "")
    extension = _parse_extension(extension_raw)

    return {
        "version": header.get("version"),
        "device_vendor": header.get("device_vendor"),
        "device_product": header.get("device_product"),
        "device_version": header.get("device_version"),
        "signature_id": header.get("signature_id"),
        "name": header.get("name"),
        "severity": header.get("severity"),
        **extension,
    }


class IDSCEFParser(BaseParser):
    """Parser for IDS/IPS CEF events."""

    parser_id = "ids_cef_v1"
    parser_name = "IDS CEF Parser v1"
    source_type = SourceType.IDS.value
    format = "cef"
    parser_version = "1.0.0"
    description = "Parses IDS/IPS CEF log events"

    def parse(self, envelope: EventEnvelope) -> ParsedEvent:
        fields = _parse_cef_line(envelope.raw.payload)
        return ParsedEvent(
            event_id=envelope.parsed.event_id if envelope.parsed else str(uuid.uuid4()),
            raw_event_id=envelope.raw_event_id,
            source_id=envelope.raw.source_id,
            source_type=envelope.raw.source_type,
            format=envelope.raw.format,
            parser_id=self.parser_id,
            parser_version=self.parser_version,
            extracted={k: v for k, v in fields.items() if v is not None},
        )
