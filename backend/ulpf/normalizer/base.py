"""Base normalizer interface for ULPF Phase 4."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ulpf.common.models import EventEnvelope, NormalizedEvent


class BaseNormalizer(ABC):
    """Abstract base class for all ULPF normalizers.

    Each normalizer must implement ``normalize`` and expose metadata through
    class attributes so the engine can discover it without hardcoding.
    """

    normalizer_id: str = ""
    normalizer_name: str = ""
    source_type: str = ""
    format: str = ""
    normalizer_version: str = "1.0.0"
    description: str = ""
    enabled: bool = True

    @abstractmethod
    def normalize(self, envelope: EventEnvelope) -> NormalizedEvent:
        """Normalize a parsed event envelope into a ``NormalizedEvent``.

        Args:
            envelope: The parsed event envelope to normalize.

        Returns:
            A ``NormalizedEvent`` with OCSF-aligned common fields and
            preserved source-specific fields.

        Raises:
            Exception: If normalization fails. The caller should catch this
                and route the event to the failed-events topic.
        """
        raise NotImplementedError

    def can_handle(self, envelope: EventEnvelope) -> bool:
        """Return True if this normalizer can handle the given envelope.

        Default implementation checks ``source_type`` and ``format`` metadata.
        """
        if not self.enabled:
            return False
        if self.source_type and envelope.parsed is not None and envelope.parsed.source_type != self.source_type:
            return False
        return not (self.format and envelope.parsed is not None and envelope.parsed.format != self.format)
