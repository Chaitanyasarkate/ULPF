"""ULPF parser package.

Provides:
- Base parser interface
- Parser registry
- Format/source detection
- Concrete parsers: syslog, json, cef
- Parser engine (Kafka consumer/producer integration)
"""

from __future__ import annotations

from ulpf.parsers.base import BaseParser
from ulpf.parsers.cef import IDSCEFParser
from ulpf.parsers.engine import ParserEngine
from ulpf.parsers.json import RouterJsonParser
from ulpf.parsers.registry import ParserRegistry
from ulpf.parsers.syslog import FirewallSyslogParser

__all__ = [
    "BaseParser",
    "FirewallSyslogParser",
    "IDSCEFParser",
    "ParserEngine",
    "ParserRegistry",
    "RouterJsonParser",
]
