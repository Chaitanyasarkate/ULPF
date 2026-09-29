"""ULPF Universal Output Conversion Engine.

This package provides pluggable output formatters for converting normalized
events to various log formats (JSON, CEF, LEEF, XML, CSV, Syslog, OCSF).

Architecture:
    NormalizedEvent (OCSF-based)
            |
            v
    ConversionService
            |
            v
    OutputFormatterRegistry
            |
            v
    Selected Formatter
            |
            v
    Converted Output (string)

Supported formats:
    - JSON: RFC 8259 compliant JSON
    - CEF: Common Event Format (HPE ArcSight)
    - LEEF: Log Event Extended Format (QRadar)
    - XML: Valid XML 1.0 with XXE protection
    - CSV: RFC 4180 compliant CSV
    - Syslog: RFC 3164/5424 compliant Syslog
    - OCSF: OCSF schema-compliant JSON
"""

from ulpf.output.base import BaseFormatter, OutputFormat
from ulpf.output.models import ConversionMetadata, ConversionResult
from ulpf.output.registry import OutputFormatterRegistry, get_formatter
from ulpf.output.service import ConversionService

__all__ = [
    "BaseFormatter",
    "ConversionMetadata",
    "ConversionResult",
    "ConversionService",
    "OutputFormat",
    "OutputFormatterRegistry",
    "get_formatter",
]
