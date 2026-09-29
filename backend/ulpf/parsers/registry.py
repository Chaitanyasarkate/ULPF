"""Parser registry for ULPF Phase 3."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from ulpf.common.models import EventEnvelope, ParsedEvent
from ulpf.parsers.base import BaseParser

logger = logging.getLogger("ulpf.parsers.registry")

if TYPE_CHECKING:
    from ulpf.common.models import EventEnvelope


class ParserRegistry:
    """Registry of available parsers.

    Parsers can be registered programmatically or loaded from YAML
    configuration files. The registry supports lookup by source type and
    format, returning the best matching parser.
    """

    def __init__(self) -> None:
        self._parsers: list[BaseParser] = []

    def register(self, parser: BaseParser) -> None:
        """Register a parser instance.

        Args:
            parser: A ``BaseParser`` subclass instance.
        """
        self._parsers.append(parser)
        logger.debug(
            "Registered parser parser_id=%s source_type=%s format=%s",
            parser.parser_id,
            parser.source_type,
            parser.format,
        )

    def lookup(self, envelope: EventEnvelope) -> BaseParser | None:
        """Find the first parser that can handle the envelope.

        Args:
            envelope: The raw event envelope.

        Returns:
            The first matching parser, or None if no parser matches.
        """
        for parser in self._parsers:
            if parser.can_handle(envelope):
                return parser
        return None

    def all_parsers(self) -> list[BaseParser]:
        """Return all registered parsers."""
        return list(self._parsers)

    def load_from_yaml(self, path: str) -> None:
        """Load parser definitions from a YAML file.

        The YAML file must contain a list of parser definitions. Each
        definition requires at least ``parser_id``, ``source_type``, and
        ``format``. Dynamic parser classes are created for each entry.

        Args:
            path: Path to the YAML file.
        """
        try:
            import yaml
        except ImportError:
            logger.warning("PyYAML is not installed; cannot load parsers from %s", path)
            return

        with open(path, "r", encoding="utf-8") as fh:
            configs = yaml.safe_load(fh) or []

        for config in configs:
            parser_cls = _build_parser_class(config)
            self.register(parser_cls())
            logger.info("Loaded parser from YAML: %s", config.get("parser_id"))


def _build_parser_class(config: dict[str, Any]) -> type[BaseParser]:
    """Dynamically create a parser class from a YAML configuration dict.

    This factory creates a minimal ``BaseParser`` subclass that delegates
    parsing to an embedded Python expression or a simple field-extraction
    map. For complex parsers, use dedicated Python modules instead.
    """
    parser_id = config.get("parser_id", "unknown")
    source_type = config.get("source_type", "")
    fmt = config.get("format", "")
    parser_version = config.get("parser_version", "1.0.0")
    description = config.get("description", "")
    field_map = config.get("field_map", {})

    class YamlParser(BaseParser):
        parser_id = parser_id
        parser_name = config.get("parser_name", parser_id)
        source_type = source_type
        format = fmt
        parser_version = parser_version
        description = description

        def parse(self, envelope: EventEnvelope) -> ParsedEvent:
            extracted: dict[str, Any] = {}
            for key, pattern in field_map.items():
                match = re.search(pattern, envelope.raw.payload)
                if match and match.lastindex is not None and match.lastindex >= 1:
                    extracted[key] = match.group(1)
                elif match:
                    extracted[key] = match.group(0)

            parsed_event = ParsedEvent(
                raw_event_id=envelope.raw_event_id,
                source_id=envelope.raw.source_id,
                source_type=envelope.raw.source_type,
                format=envelope.raw.format,
                parser_id=self.parser_id,
                parser_version=self.parser_version,
                extracted=extracted,
            )
            return parsed_event

    YamlParser.__name__ = parser_id
    return YamlParser
