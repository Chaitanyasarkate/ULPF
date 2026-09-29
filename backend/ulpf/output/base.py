"""Base formatter interface for ULPF Phase 9A output conversion."""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ulpf.common.models import NormalizedEvent


class OutputFormat(str, enum.Enum):
    """Supported output formats for event conversion."""

    JSON = "json"
    CEF = "cef"
    LEEF = "leef"
    XML = "xml"
    CSV = "csv"
    SYSLOG = "syslog"
    OCSF = "ocsf"

    @classmethod
    def from_string(cls, value: str) -> OutputFormat:
        """Parse format from string, case-insensitive."""
        normalized = value.lower().strip()
        for fmt in cls:
            if fmt.value == normalized:
                return fmt
        valid = ", ".join(f.value for f in cls)
        raise ValueError(f"Unknown output format '{value}'. Valid formats: {valid}")


class BaseFormatter(ABC):
    """Abstract base class for all ULPF output formatters.

    Each formatter must implement the ``format`` method and expose metadata
    through class attributes so the registry can discover it.
    """

    formatter_id: str = ""
    formatter_name: str = ""
    formatter_version: str = "1.0.0"
    output_format: OutputFormat = OutputFormat.JSON
    description: str = ""
    enabled: bool = True

    @abstractmethod
    def format(self, event: NormalizedEvent) -> str:
        """Format a normalized event into a string representation.

        Args:
            event: The normalized event to format.

        Returns:
            Formatted string representation of the event.

        Raises:
            Exception: If formatting fails. Callers should handle this gracefully.
        """
        raise NotImplementedError

    def can_handle(self, fmt: OutputFormat) -> bool:
        """Return True if this formatter handles the given output format."""
        if not self.enabled:
            return False
        return self.output_format == fmt

    def get_metadata(self) -> dict[str, Any]:
        """Return formatter metadata for API responses."""
        return {
            "formatter_id": self.formatter_id,
            "formatter_name": self.formatter_name,
            "formatter_version": self.formatter_version,
            "output_format": self.output_format.value,
            "description": self.description,
        }
