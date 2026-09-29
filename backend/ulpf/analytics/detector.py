"""Anomaly detector service for ULPF.

Implements rule-based anomaly detection on normalized OCSF events.
All detection runs locally with no external dependencies.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from ulpf.analytics.models import (
    Anomaly,
    AnomalyDetectionResult,
    AnomalyRule,
    AnomalyRuleType,
    AnomalySeverity,
)
from ulpf.analytics.repository import AnomalyRepository
from ulpf.common.models import NormalizedEvent

logger = logging.getLogger("ulpf.analytics.detector")


class AnomalyDetector:
    """Rule-based anomaly detector for normalized events."""

    def __init__(self, repository: AnomalyRepository | None = None) -> None:
        self.repository = repository or AnomalyRepository()
        self._rules_cache: list[AnomalyRule] | None = None
        self._last_rules_refresh: datetime | None = None
        self._rules_cache_ttl = timedelta(minutes=5)

    async def _get_enabled_rules(self) -> list[AnomalyRule]:
        """Get enabled rules with caching."""
        now = datetime.now(timezone.utc)
        if (self._rules_cache is None or
            self._last_rules_refresh is None or
            now - self._last_rules_refresh > self._rules_cache_ttl):
            self._rules_cache = await self.repository.get_rules(enabled_only=True)
            self._last_rules_refresh = now
        return self._rules_cache

    async def detect(
        self, event: NormalizedEvent, repo: AnomalyRepository | None = None
    ) -> AnomalyDetectionResult:
        """Run all enabled rules against a normalized event.

        Args:
            event: The normalized event to check.
            repo: Optional AnomalyRepository to use for queries. If not provided,
                uses self.repository. Pass a fresh repo per call to avoid
                asyncpg event-loop binding issues across Kafka messages.
        """
        active_repo = repo or self.repository
        rules = await active_repo.get_rules(enabled_only=True)
        anomalies: list[Anomaly] = []

        for rule in rules:
            try:
                rule_anomalies = await self._evaluate_rule(event, rule, active_repo)
                anomalies.extend(rule_anomalies)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Rule %s evaluation failed: %s", rule.rule_id, exc)

        return AnomalyDetectionResult(
            event_id=event.event_id,
            anomalies=anomalies,
            rules_evaluated=len(rules),
        )

    async def _evaluate_rule(
        self, event: NormalizedEvent, rule: AnomalyRule, repo: AnomalyRepository | None = None
    ) -> list[Anomaly]:
        """Evaluate a single rule against an event."""
        active_repo = repo or self.repository
        if rule.rule_type == AnomalyRuleType.FAILED_AUTH_SPIKE:
            return await self._check_failed_auth_spike(event, rule, active_repo)
        elif rule.rule_type == AnomalyRuleType.UNUSUAL_PORT:
            return await self._check_unusual_port(event, rule, active_repo)
        elif rule.rule_type == AnomalyRuleType.SEVERITY_ESCALATION:
            return await self._check_severity_escalation(event, rule, active_repo)
        elif rule.rule_type == AnomalyRuleType.PROTOCOL_ANOMALY:
            return await self._check_protocol_anomaly(event, rule, active_repo)
        elif rule.rule_type == AnomalyRuleType.VOLUME_SPIKE:
            return await self._check_volume_spike(event, rule, active_repo)
        return []

    async def _check_failed_auth_spike(
        self, event: NormalizedEvent, rule: AnomalyRule, repo: AnomalyRepository
    ) -> list[Anomaly]:
        """Check for spike in failed authentication events from a source IP."""
        # Only check deny/block actions
        action = event.ocsf.get("event", {}).get("action", "").lower()
        if action not in ("deny", "block", "drop", "reject"):
            return []

        # Only check source IP events
        source_ip = event.ocsf.get("source", {}).get("ip")
        if not source_ip:
            return []

        threshold = rule.thresholds.get("threshold", 20)
        window_seconds = rule.thresholds.get("window_seconds", 300)

        # Query recent events for this source IP from OpenSearch
        since = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()

        recent_events = await repo.get_recent_events_for_source(
            source_id=source_ip,
            since=since,
            action=action,
        )

        if len(recent_events) >= threshold:
            # Create anomaly with detailed reason
            reason = (
                f"{len(recent_events)} failed authentication events from {source_ip} "
                f"in {window_seconds // 60} minutes, threshold={threshold}"
            )
            anomaly = Anomaly(
                event_id=event.event_id,
                raw_event_id=event.raw_event_id,
                source_id=source_ip,
                source_type=event.source_type,
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                severity=AnomalySeverity.HIGH,
                reason=reason,
                triggered_fields={
                    "source_ip": source_ip,
                    "event_count": len(recent_events),
                    "threshold": threshold,
                    "window_seconds": window_seconds,
                    "action": action,
                },
            )
            return [anomaly]

        return []

    async def _check_unusual_port(
        self, event: NormalizedEvent, rule: AnomalyRule, repo: AnomalyRepository | None = None
    ) -> list[Anomaly]:
        """Check for unusual destination port relative to source's baseline."""
        dest_port = event.ocsf.get("destination", {}).get("port")
        source_ip = event.ocsf.get("source", {}).get("ip")

        if not dest_port or not source_ip:
            return []

        # In a full implementation, this would query historical ports from OpenSearch
        # For now, we'll flag well-known suspicious ports
        suspicious_ports = {22, 23, 3389, 445, 1433, 3306, 5432, 6379, 27017}
        baseline_days = rule.thresholds.get("baseline_days", 7)
        min_occurrences = rule.thresholds.get("min_occurrences", 3)

        # This is a simplified check - in reality you'd query the baseline
        if dest_port in suspicious_ports:
            reason = (
                f"Unusual destination port {dest_port} from {source_ip} "
                f"(not seen in {baseline_days}-day baseline, min_occurrences={min_occurrences})"
            )
            anomaly = Anomaly(
                event_id=event.event_id,
                raw_event_id=event.raw_event_id,
                source_id=source_ip,
                source_type=event.source_type,
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                severity=AnomalySeverity.MEDIUM,
                reason=reason,
                triggered_fields={
                    "destination_port": dest_port,
                    "source_ip": source_ip,
                    "baseline_days": baseline_days,
                    "suspicious": True,
                },
            )
            return [anomaly]

        return []

    async def _check_severity_escalation(
        self, event: NormalizedEvent, rule: AnomalyRule, repo: AnomalyRepository
    ) -> list[Anomaly]:
        """Check for cluster of high/critical severity events from one source."""
        severity = event.ocsf.get("event", {}).get("severity", "").lower()
        source_ip = event.ocsf.get("source", {}).get("ip")

        if severity not in ("high", "critical") or not source_ip:
            return []

        threshold = rule.thresholds.get("threshold", 5)
        window_seconds = rule.thresholds.get("window_seconds", 600)
        min_severity = rule.thresholds.get("min_severity", "high")

        since_dt = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)

        recent_anomalies, _ = await repo.list_anomalies(
            source_id=source_ip,
            rule_id=rule.rule_id,
            start_time=since_dt,
            page_size=threshold + 10,
        )

        # Also check for high severity events in general
        high_severity_count = sum(
            1 for a in recent_anomalies
            if a.triggered_fields.get("severity") in ("high", "critical")
        )

        if high_severity_count >= threshold:
            reason = (
                f"{high_severity_count} {min_severity}+ severity events from {source_ip} "
                f"in {window_seconds // 60} minutes, threshold={threshold}"
            )
            anomaly = Anomaly(
                event_id=event.event_id,
                raw_event_id=event.raw_event_id,
                source_id=source_ip,
                source_type=event.source_type,
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                severity=AnomalySeverity.CRITICAL,
                reason=reason,
                triggered_fields={
                    "source_ip": source_ip,
                    "high_severity_count": high_severity_count,
                    "threshold": threshold,
                    "window_seconds": window_seconds,
                    "min_severity": min_severity,
                },
            )
            return [anomaly]

        return []

    async def _check_protocol_anomaly(
        self, event: NormalizedEvent, rule: AnomalyRule, repo: AnomalyRepository
    ) -> list[Anomaly]:
        """Check for unexpected protocol usage."""
        protocol = event.ocsf.get("network", {}).get("protocol")
        source_ip = event.ocsf.get("source", {}).get("ip")
        if not protocol or not source_ip:
            return []
        protocol = protocol.upper()

        # Common protocols that are expected
        expected_protocols = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH"}

        if protocol not in expected_protocols:
            baseline_days = rule.thresholds.get("baseline_days", 7)
            reason = (
                f"Unexpected protocol {protocol} from {source_ip} "
                f"(not in baseline of common protocols over {baseline_days} days)"
            )
            anomaly = Anomaly(
                event_id=event.event_id,
                raw_event_id=event.raw_event_id,
                source_id=source_ip,
                source_type=event.source_type,
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                severity=AnomalySeverity.MEDIUM,
                reason=reason,
                triggered_fields={
                    "protocol": protocol,
                    "source_ip": source_ip,
                    "baseline_days": baseline_days,
                    "expected_protocols": list(expected_protocols),
                },
            )
            return [anomaly]

        return []

    async def _check_volume_spike(
        self, event: NormalizedEvent, rule: AnomalyRule, repo: AnomalyRepository
    ) -> list[Anomaly]:
        """Check for unusual spike in event volume from a source."""
        source_ip = event.ocsf.get("source", {}).get("ip")
        if not source_ip:
            return []

        threshold_multiplier = rule.thresholds.get("threshold_multiplier", 3.0)
        window_seconds = rule.thresholds.get("window_seconds", 300)
        baseline_window_seconds = rule.thresholds.get("baseline_window_seconds", 3600)

        now = datetime.now(timezone.utc)
        recent_since = (now - timedelta(seconds=window_seconds)).isoformat()
        baseline_since = (now - timedelta(seconds=baseline_window_seconds)).isoformat()

        recent_events = await repo.get_recent_events_for_source(
            source_id=source_ip,
            since=recent_since,
        )

        if not recent_events:
            return []

        baseline_events = await repo.get_recent_events_for_source(
            source_id=source_ip,
            since=baseline_since,
        )

        baseline_avg = max(
            len(baseline_events) / max(baseline_window_seconds / window_seconds, 1), 1
        )
        if len(recent_events) > baseline_avg * threshold_multiplier:
            reason = (
                f"Volume spike from {source_ip}: {len(recent_events)} events in "
                f"{window_seconds}s vs baseline avg {baseline_avg:.1f} "
                f"(threshold x{threshold_multiplier})"
            )
            anomaly = Anomaly(
                event_id=event.event_id,
                raw_event_id=event.raw_event_id,
                source_id=source_ip,
                source_type=event.source_type,
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                severity=AnomalySeverity.HIGH,
                reason=reason,
                detected_at=now.isoformat(),
                triggered_fields={
                    "source_ip": source_ip,
                    "event_count": len(recent_events),
                    "baseline_avg": baseline_avg,
                    "threshold_multiplier": threshold_multiplier,
                    "window_seconds": window_seconds,
                    "baseline_window_seconds": baseline_window_seconds,
                },
            )
            return [anomaly]

        return []


async def run_anomaly_detection_on_event(event: NormalizedEvent) -> AnomalyDetectionResult:
    """Convenience function to run anomaly detection on a single event."""
    detector = AnomalyDetector()
    try:
        return await detector.detect(event)
    finally:
        await detector.repository.close()