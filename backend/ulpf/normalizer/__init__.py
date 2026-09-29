"""ULPF normalizer package.

Provides:
- Base normalizer interface
- OCSF-based normalizers for firewall, router, IDS
- Normalizer engine with Kafka integration
- Field mappings and validation helpers
"""

from __future__ import annotations

from ulpf.normalizer.base import BaseNormalizer
from ulpf.normalizer.engine import NormalizerEngine, OCSFNormalizer
from ulpf.normalizer.mappings import (
    normalize_action,
    normalize_severity,
    normalize_timestamp,
)
from ulpf.normalizer.validation import validate_ip, validate_port, validate_protocol

__all__ = [
    "BaseNormalizer",
    "NormalizerEngine",
    "OCSFNormalizer",
    "normalize_action",
    "normalize_severity",
    "normalize_timestamp",
    "validate_ip",
    "validate_port",
    "validate_protocol",
]
