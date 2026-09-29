"""ULPF Phase 6 Event Lineage & Traceability.

Provides traceability between raw, parsed, and normalized events.

Design:
- Raw Event (raw_event_id) -> Parsed Event (event_id) -> Normalized Event (event_id)
- Explicit lineage relationships stored in PostgreSQL
- Raw events recovered from MinIO
- Normalized events retrieved from OpenSearch
- Complete SHA-256 verification

Usage:
    service = LineageService()
    await service.initialize()

    # Record lineage
    await service.record_parsing_lineage(envelope)
    await service.record_normalization_lineage(envelope)

    # Query lineage
    chain = await service.get_lineage_chain(event_id)
    raw = await service.recover_raw_event(event_id)
    verification = await service.verify_lineage(event_id)
"""

from __future__ import annotations

from ulpf.lineage.api import lineage_bp, register_lineage_blueprint
from ulpf.lineage.models import (
    LineageChain,
    LineageRecord,
    LineageVerification,
    RawEventRecovery,
    RelationshipType,
    VerificationStatus,
)
from ulpf.lineage.repository import LineageRepository
from ulpf.lineage.service import LineageService

__all__ = [
    "LineageChain",
    "LineageRecord",
    "LineageRepository",
    "LineageService",
    "LineageVerification",
    "RawEventRecovery",
    "RelationshipType",
    "VerificationStatus",
    "lineage_bp",
    "register_lineage_blueprint",
]
