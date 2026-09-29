"""Source profile models for ULPF Phase 7."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SourceType(str, Enum):
    FIREWALL = "firewall"
    ROUTER = "router"
    IDS = "ids"
    IPS = "ips"
    VPN = "vpn"
    SWITCH = "switch"
    SERVER = "server"
    APPLICATION = "application"
    CUSTOM = "custom"
    UNKNOWN = "unknown"

    @classmethod
    def values(cls) -> list[str]:
        return [e.value for e in cls]


class LogFormat(str, Enum):
    SYSLOG = "syslog"
    JSON = "json"
    CEF = "cef"
    LEEF = "leef"
    CSV = "csv"
    XML = "xml"
    CUSTOM = "custom"
    UNKNOWN = "unknown"

    @classmethod
    def values(cls) -> list[str]:
        return [e.value for e in cls]


class SourceStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"

    @classmethod
    def values(cls) -> list[str]:
        return [e.value for e in cls]


@dataclass
class SourceProfile:
    """Configuration profile for a log source.

    Defines how incoming events from a specific source should be processed,
    including parser selection, normalization mapping, and schema versioning.
    """

    source_id: str
    source_name: str
    source_type: str
    format: str
    parser_id: str
    parser_version: str = "1.0.0"
    normalizer_id: str | None = None
    normalizer_version: str | None = None
    schema_version: str = "1.0.0"
    enabled: bool = True
    status: str = SourceStatus.ACTIVE.value
    vendor: str | None = None
    product: str | None = None
    product_version: str | None = None
    description: str | None = None
    transport: str | None = None
    configuration: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utcnow_iso)
    updated_at: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_name": self.source_name,
            "source_type": self.source_type,
            "format": self.format,
            "parser_id": self.parser_id,
            "parser_version": self.parser_version,
            "normalizer_id": self.normalizer_id,
            "normalizer_version": self.normalizer_version,
            "schema_version": self.schema_version,
            "enabled": self.enabled,
            "status": self.status,
            "vendor": self.vendor,
            "product": self.product,
            "product_version": self.product_version,
            "description": self.description,
            "transport": self.transport,
            "configuration": dict(self.configuration),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SourceProfile:
        return cls(
            source_id=data["source_id"],
            source_name=data["source_name"],
            source_type=data["source_type"],
            format=data["format"],
            parser_id=data["parser_id"],
            parser_version=data.get("parser_version", "1.0.0"),
            normalizer_id=data.get("normalizer_id"),
            normalizer_version=data.get("normalizer_version"),
            schema_version=data.get("schema_version", "1.0.0"),
            enabled=data.get("enabled", True),
            status=data.get("status", SourceStatus.ACTIVE.value),
            vendor=data.get("vendor"),
            product=data.get("product"),
            product_version=data.get("product_version"),
            description=data.get("description"),
            transport=data.get("transport"),
            configuration=data.get("configuration", {}),
            created_at=data.get("created_at", _utcnow_iso()),
            updated_at=data.get("updated_at", _utcnow_iso()),
        )

    def update(self) -> None:
        self.updated_at = _utcnow_iso()
