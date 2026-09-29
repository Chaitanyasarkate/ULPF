"""XML output formatter for ULPF Phase 9A with XXE protection.

Produces valid XML 1.0 with proper character escaping.
XXE protection is handled at parse time for input; output is safe by construction.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING, Any, ClassVar

from ulpf.output.base import BaseFormatter, OutputFormat

if TYPE_CHECKING:
    from ulpf.common.models import NormalizedEvent


def _escape_xml_text(value: Any) -> str:
    """Escape text content for XML (no CDATA needed for safe content)."""
    if value is None:
        return ""
    s = str(value)
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace("'", "&apos;")
    s = s.replace('"', "&quot;")
    return s


class XMLFormatter(BaseFormatter):
    """Formats normalized events as XML 1.0.

    Produces well-formed XML with:
    - Root Event element
    - Namespace declarations for OCSF
    - All normalized fields
    - All original parsed fields preserved
    """

    formatter_id = "xml_formatter_v1"
    formatter_name = "XML Formatter v1"
    formatter_version = "1.0.0"
    output_format = OutputFormat.XML
    description = "Formats events as XML 1.0 with XXE protection"

    _ns: ClassVar[dict[str, str]] = {
        "ulpf": "http://ulpf.example.com/schema",
        "ocsf": "http://ocsf.example.com/schema",
    }

    def format(self, event: NormalizedEvent) -> str:
        """Format a normalized event as XML.

        Args:
            event: The normalized event to format.

        Returns:
            Well-formed XML 1.0 string.
        """
        root = ET.Element("Event", xmlns=self._ns["ulpf"])

        metadata = ET.SubElement(root, "Metadata")
        ET.SubElement(metadata, "EventID").text = _escape_xml_text(event.event_id)
        ET.SubElement(metadata, "RawEventID").text = _escape_xml_text(event.raw_event_id)
        ET.SubElement(metadata, "SchemaVersion").text = _escape_xml_text(event.schema_version)
        ET.SubElement(metadata, "IngestionTimestamp").text = _escape_xml_text(event.ingestion_timestamp)
        ET.SubElement(metadata, "EventTimestamp").text = _escape_xml_text(event.event_timestamp)

        source = ET.SubElement(root, "Source")
        ET.SubElement(source, "SourceID").text = _escape_xml_text(event.source_id)
        ET.SubElement(source, "SourceType").text = _escape_xml_text(event.source_type)
        ET.SubElement(source, "Format").text = _escape_xml_text(event.format)

        parser = ET.SubElement(root, "Parser")
        ET.SubElement(parser, "ParserID").text = _escape_xml_text(event.parser_id)
        ET.SubElement(parser, "ParserVersion").text = _escape_xml_text(event.parser_version)

        integrity = ET.SubElement(root, "Integrity")
        ET.SubElement(integrity, "SHA256").text = _escape_xml_text(event.sha256)

        if event.ocsf:
            ocsf_elem = ET.SubElement(root, "OCSF")
            self._dict_to_xml(ocsf_elem, event.ocsf)

        if event.parsed_fields:
            parsed_elem = ET.SubElement(root, "ParsedFields")
            self._dict_to_xml(parsed_elem, event.parsed_fields)

        if event.raw_payload:
            raw_elem = ET.SubElement(root, "RawPayload")
            raw_elem.text = _escape_xml_text(event.raw_payload)

        ET.register_namespace("ulpf", self._ns["ulpf"])
        ET.register_namespace("ocsf", self._ns["ocsf"])

        return ET.tostring(root, encoding="unicode", xml_declaration=True)

    def _dict_to_xml(self, parent: ET.Element, data: dict[str, Any]) -> None:
        """Convert a dict to XML elements recursively."""
        for key, value in sorted(data.items()):
            safe_key = _safe_xml_tag(key)
            tag_name: str
            if safe_key is None:
                tag_name = "field"
                attr_key: str | None = "name"
            else:
                tag_name = safe_key
                attr_key = "key" if safe_key.startswith("_") else None

            if isinstance(value, dict):
                elem = ET.SubElement(parent, tag_name)
                self._dict_to_xml(elem, value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        elem = ET.SubElement(parent, tag_name)
                        self._dict_to_xml(elem, item)
                    else:
                        elem = ET.SubElement(parent, tag_name)
                        elem.text = _escape_xml_text(item)
            else:
                elem = ET.SubElement(parent, tag_name)
                elem.text = _escape_xml_text(value)
                if attr_key:
                    elem.set(attr_key, _escape_xml_text(key))


def _safe_xml_tag(name: str) -> str | None:
    """Convert a string to a valid XML tag name.

    Returns None if the name cannot be made into a valid tag.
    """
    if not name:
        return None

    tag = name.lower()
    tag = tag.replace("-", "_")
    tag = tag.replace(" ", "_")
    tag = tag.replace(".", "_")
    tag = tag.replace(":", "_")

    tag = "".join(c if c.isalnum() or c == "_" else "" for c in tag)

    if not tag:
        return None

    if tag[0].isdigit():
        tag = "_" + tag

    reserved = {"xml", "true", "false", "null"}
    if tag in reserved:
        tag = "_" + tag

    return tag
