"""Base parser interface for ULPF Phase 3."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ulpf.common.models import EventEnvelope, ParsedEvent


class BaseParser(ABC):
    """Abstract base class for all ULPF parsers.

    Each parser must implement ``parse`` and expose metadata through class
    attributes so the registry can discover it without hardcoding.
    """

    parser_id: str = ""
    parser_name: str = ""
    source_type: str = ""
    format: str = ""
    parser_version: str = "1.0.0"
    description: str = ""
    enabled: bool = True

    @abstractmethod
    def parse(self, envelope: EventEnvelope) -> ParsedEvent:
        """Parse a raw event envelope into a structured ``ParsedEvent``.

        Args:
            envelope: The raw event envelope to parse.

        Returns:
            A ``ParsedEvent`` with extracted fields.

        Raises:
            Exception: If parsing fails. The caller should catch this and route
                the event to the failed-events topic.
        """
        raise NotImplementedError

    def can_handle(self, envelope: EventEnvelope) -> bool:
        """Return True if this parser can handle the given envelope.

        Default implementation checks ``source_type`` and ``format`` metadata.
        Subclasses may override for more nuanced detection.
        """
        if not self.enabled:
            return False
        if self.source_type and envelope.raw.source_type != self.source_type:
            return False
        return not (self.format and envelope.raw.format != self.format)
