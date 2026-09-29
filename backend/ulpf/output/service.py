"""Conversion service for ULPF Phase 9A."""

from __future__ import annotations

import logging
from typing import Any

from ulpf.common.models import SCHEMA_VERSION, NormalizedEvent
from ulpf.output.base import BaseFormatter, OutputFormat
from ulpf.output.models import ConversionMetadata, ConversionResult
from ulpf.output.registry import OutputFormatterRegistry, UnknownFormatError

logger = logging.getLogger("ulpf.output.service")


class ConversionError(Exception):
    """Raised when conversion fails."""


class ConversionService:
    """Service for converting normalized events to various output formats.

    The service does not modify the original normalized event. Every conversion
    returns metadata including formatter info, timestamps, and any warnings
    about fields that couldn't be represented in the target format.
    """

    def __init__(self, registry: OutputFormatterRegistry | None = None) -> None:
        self._registry = registry or OutputFormatterRegistry.get_instance()

    def convert(
        self,
        event: NormalizedEvent,
        output_format: OutputFormat | str,
    ) -> ConversionResult:
        """Convert a normalized event to the specified output format.

        Args:
            event: The normalized event to convert.
            output_format: Target output format (enum or string).

        Returns:
            ConversionResult with metadata and formatted payload.

        Raises:
            ConversionError: If conversion fails.
            UnknownFormatError: If the format is not supported.
        """
        try:
            formatter = self._registry.get_formatter(output_format)
        except UnknownFormatError:
            logger.warning(
                "Unknown output format requested: %s for event_id=%s",
                output_format,
                event.event_id,
            )
            raise

        try:
            payload = formatter.format(event)
        except Exception as exc:
            logger.error(
                "Formatter %s failed for event_id=%s: %s",
                formatter.formatter_id,
                event.event_id,
                exc,
            )
            raise ConversionError(
                f"Formatter {formatter.formatter_id} failed: {exc}"
            ) from exc

        metadata = ConversionMetadata(
            event_id=event.event_id,
            raw_event_id=event.raw_event_id,
            input_format=event.format or "ocsf",
            output_format=formatter.output_format.value,
            formatter_id=formatter.formatter_id,
            formatter_version=formatter.formatter_version,
            schema_version=event.schema_version or SCHEMA_VERSION,
        )

        warnings = self._check_field_representation(event, formatter)

        return ConversionResult(
            metadata=metadata,
            payload=payload,
            original_event_preserved=True,
            custom_fields_preserved=len(warnings) == 0,
            warnings=warnings,
        )

    def _check_field_representation(
        self,
        event: NormalizedEvent,
        formatter: BaseFormatter,
    ) -> list[str]:
        """Check if all fields can be represented in the target format.

        Returns a list of warnings for fields that may be lost.
        """
        warnings: list[str] = []
        parsed_fields = event.parsed_fields or {}

        if not parsed_fields:
            return warnings

        standard_fields = {
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "action", "severity", "host", "timestamp", "message",
            "src", "dst", "act", "proto",
        }

        extra_fields = set(parsed_fields.keys()) - standard_fields

        if extra_fields:
            fmt = formatter.output_format.value.upper()
            warnings.append(
                f"{fmt}: {len(extra_fields)} non-standard field(s) may be preserved "
                f"in extension attributes: {sorted(extra_fields)}"
            )

        return warnings

    def get_available_formats(self) -> list[dict[str, Any]]:
        """Return list of available formats with metadata."""
        return [f.get_metadata() for f in self._registry.all_formatters()]
