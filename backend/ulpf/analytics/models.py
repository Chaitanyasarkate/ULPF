"""Anomaly detection models for ULPF.

Defines the data structures for rule-based anomalies detected on normalized events.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class AnomalySeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def values(cls) -> list[str]:
        return [s.value for s in cls]


class AnomalyStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"

    @classmethod
    def values(cls) -> list[str]:
        return [s.value for s in cls]


class AnomalyRuleType(str, Enum):
    FAILED_AUTH_SPIKE = "failed_auth_spike"
    UNUSUAL_PORT = "unusual_port"
    SEVERITY_ESCALATION = "severity_escalation"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    VOLUME_SPIKE = "volume_spike"

    @classmethod
    def values(cls) -> list[str]:
        return [r.value for r in cls]


@dataclass(frozen=True)
class AnomalyRule:
    """Configuration for an anomaly detection rule."""

    rule_id: str
    rule_name: str
    rule_type: AnomalyRuleType
    description: str
    enabled: bool = True
    # Rule-specific thresholds (JSON-serializable)
    thresholds: dict[str, Any] = field(default_factory=dict)
    # Minimum time between anomalies for same source (seconds)
    cooldown_seconds: int = 300
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass(frozen=True)
class Anomaly:
    """A detected anomaly with human-readable explanation."""

    anomaly_id: str = field(default_factory=lambda: f"anom-{uuid4().hex[:12]}")
    event_id: str = ""
    raw_event_id: str = ""
    source_id: str = ""
    source_type: str = ""
    rule_id: str = ""
    rule_name: str = ""
    severity: AnomalySeverity = AnomalySeverity.MEDIUM
    reason: str = ""
    triggered_fields: dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: AnomalyStatus = AnomalyStatus.OPEN
    acknowledged_by: str | None = None
    acknowledged_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "event_id": self.event_id,
            "raw_event_id": self.raw_event_id,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "reason": self.reason,
            "triggered_fields": self.triggered_fields,
            "detected_at": self.detected_at.isoformat() if isinstance(self.detected_at, datetime) else str(self.detected_at),
            "status": self.status.value,
            "acknowledged_by": self.acknowledged_by,
            "acknowledged_at": self.acknowledged_at.isoformat() if isinstance(self.acknowledged_at, datetime) else str(self.acknowledged_at) if self.acknowledged_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Anomaly:
        detected_at = data.get("detected_at", datetime.now(timezone.utc))
        if isinstance(detected_at, str):
            detected_at = datetime.fromisoformat(detected_at.replace("Z", "+00:00"))
        acknowledged_at = data.get("acknowledged_at")
        if isinstance(acknowledged_at, str):
            acknowledged_at = datetime.fromisoformat(acknowledged_at.replace("Z", "+00:00"))
        return cls(
            anomaly_id=data.get("anomaly_id", f"anom-{uuid4().hex[:12]}"),
            event_id=data.get("event_id", ""),
            raw_event_id=data.get("raw_event_id", ""),
            source_id=data.get("source_id", ""),
            source_type=data.get("source_type", ""),
            rule_id=data.get("rule_id", ""),
            rule_name=data.get("rule_name", ""),
            severity=AnomalySeverity(data.get("severity", "medium")),
            reason=data.get("reason", ""),
            triggered_fields=data.get("triggered_fields", {}),
            detected_at=detected_at,
            status=AnomalyStatus(data.get("status", "open")),
            acknowledged_by=data.get("acknowledged_by"),
            acknowledged_at=acknowledged_at,
        )


@dataclass(frozen=True)
class AnomalyDetectionResult:
    """Result of running anomaly detection on an event."""

    event_id: str
    anomalies: list[Anomaly] = field(default_factory=list)
    rules_evaluated: int = 0

    def has_anomalies(self) -> bool:
        return len(self.anomalies) > 0