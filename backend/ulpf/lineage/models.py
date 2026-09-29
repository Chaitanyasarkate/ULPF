"""Lineage models for ULPF Phase 6.

Defines the lineage relationship model for traceability between events.

Design:
- Raw Event (raw_event_id) -> Parsed Event (event_id) -> Normalized Event (event_id)
- Uses generic parent/child relationships for flexibility
- Relationship types: parsed_from, normalized_from
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class RelationshipType(str, Enum):
    """Types of lineage relationships between events."""

    PARSED_FROM = "parsed_from"
    NORMALIZED_FROM = "normalized_from"
    DERIVED_FROM = "derived_from"


class VerificationStatus(str, Enum):
    """Status of lineage verification."""

    VALID = "valid"
    INVALID = "invalid"
    UNCHECKED = "unchecked"
    UNAVAILABLE = "unavailable"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class LineageRecord:
    """A single lineage relationship between two events.

    Records the relationship between a parent event and a child event,
    enabling traceability from normalized events back to their original
    raw events and vice versa.
    """

    parent_event_id: str
    child_event_id: str
    relationship_type: RelationshipType
    raw_event_id: str
    created_at: str = field(default_factory=_utcnow_iso)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent_event_id": self.parent_event_id,
            "child_event_id": self.child_event_id,
            "relationship_type": self.relationship_type.value,
            "raw_event_id": self.raw_event_id,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LineageRecord:
        return cls(
            parent_event_id=data["parent_event_id"],
            child_event_id=data["child_event_id"],
            relationship_type=RelationshipType(data["relationship_type"]),
            raw_event_id=data["raw_event_id"],
            created_at=data.get("created_at", _utcnow_iso()),
            metadata=data.get("metadata", {}),
        )


@dataclass
class LineageChain:
    """A complete lineage chain for an event.

    Contains all ancestors and descendants of an event, enabling
    full traceability from raw event to normalized event.
    """

    event_id: str
    raw_event_id: str
    ancestors: list[LineageRecord] = field(default_factory=list)
    descendants: list[LineageRecord] = field(default_factory=list)
    sha256: str = ""
    parser_id: str = ""
    parser_version: str = ""
    schema_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "raw_event_id": self.raw_event_id,
            "ancestors": [a.to_dict() for a in self.ancestors],
            "descendants": [d.to_dict() for d in self.descendants],
            "sha256": self.sha256,
            "parser_id": self.parser_id,
            "parser_version": self.parser_version,
            "schema_version": self.schema_version,
        }


@dataclass
class LineageVerification:
    """Result of lineage verification for an event.

    Provides structured verification results for forensic analysis.
    """

    event_id: str
    raw_event_id: str
    status: VerificationStatus = VerificationStatus.UNCHECKED
    sha256_verified: bool | None = None
    raw_object_exists: bool | None = None
    normalized_object_exists: bool | None = None
    lineage_complete: bool | None = None
    lineage_chain: LineageChain | None = None
    raw_payload: str | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "event_id": self.event_id,
            "raw_event_id": self.raw_event_id,
            "status": self.status.value,
            "sha256_verified": self.sha256_verified,
            "raw_object_exists": self.raw_object_exists,
            "normalized_object_exists": self.normalized_object_exists,
            "lineage_complete": self.lineage_complete,
            "errors": list(self.errors),
        }
        if self.lineage_chain:
            result["lineage_chain"] = self.lineage_chain.to_dict()
        if self.raw_payload:
            result["raw_payload"] = self.raw_payload
        return result

    @property
    def is_valid(self) -> bool:
        return self.status == VerificationStatus.VALID

    @property
    def is_invalid(self) -> bool:
        return self.status == VerificationStatus.INVALID

    @property
    def is_unavailable(self) -> bool:
        return self.status == VerificationStatus.UNAVAILABLE


@dataclass
class RawEventRecovery:
    """Result of recovering a raw event from MinIO.

    Contains the raw payload and verification status.
    """

    raw_event_id: str
    sha256: str
    expected_sha256: str
    raw_payload: str | None = None
    object_key: str | None = None
    bucket: str | None = None
    exists: bool = False
    verified: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_event_id": self.raw_event_id,
            "sha256": self.sha256,
            "expected_sha256": self.expected_sha256,
            "raw_payload": self.raw_payload,
            "object_key": self.object_key,
            "bucket": self.bucket,
            "exists": self.exists,
            "verified": self.verified,
            "error": self.error,
        }

    @property
    def integrity_ok(self) -> bool:
        return self.exists and self.verified and self.sha256 == self.expected_sha256
