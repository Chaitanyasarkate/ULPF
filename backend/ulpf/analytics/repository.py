"""Anomaly repository for ULPF - PostgreSQL storage."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import asyncpg

from ulpf.analytics.models import (
    Anomaly,
    AnomalyRule,
    AnomalyRuleType,
    AnomalySeverity,
    AnomalyStatus,
)
from ulpf.config import get_settings

logger = logging.getLogger("ulpf.analytics.repository")


class AnomalyRepository:
    """PostgreSQL repository for anomaly storage and retrieval."""

    def __init__(self) -> None:
        settings = get_settings()
        self._dsn = (
            f"postgresql://{settings.postgres.user}:{settings.postgres.password}"
            f"@{settings.postgres.host}:{settings.postgres.port}/{settings.postgres.db}"
        )
        self._pool: asyncpg.Pool | None = None

    async def _get_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            self._pool = await asyncpg.create_pool(
                self._dsn,
                min_size=1,
                max_size=5,
            )
        return self._pool

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None

    async def initialize_schema(self) -> None:
        """Create anomaly tables if they don't exist."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            # Anomalies table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    anomaly_id VARCHAR(64) PRIMARY KEY,
                    event_id VARCHAR(64) NOT NULL,
                    raw_event_id VARCHAR(64) NOT NULL,
                    source_id VARCHAR(128) NOT NULL,
                    source_type VARCHAR(64) NOT NULL,
                    rule_id VARCHAR(64) NOT NULL,
                    rule_name VARCHAR(256) NOT NULL,
                    severity VARCHAR(16) NOT NULL,
                    reason TEXT NOT NULL,
                    triggered_fields JSONB NOT NULL DEFAULT '{}',
                    detected_at TIMESTAMPTZ NOT NULL,
                    status VARCHAR(16) NOT NULL DEFAULT 'open',
                    acknowledged_by VARCHAR(128),
                    acknowledged_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)

            # Indexes for common queries
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_anomalies_event_id ON anomalies(event_id)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_anomalies_raw_event_id ON anomalies(raw_event_id)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_anomalies_source_id ON anomalies(source_id)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_anomalies_rule_id ON anomalies(rule_id)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_anomalies_detected_at ON anomalies(detected_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_anomalies_status ON anomalies(status)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies(severity)
            """)

            # Anomaly rules table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS anomaly_rules (
                    rule_id VARCHAR(64) PRIMARY KEY,
                    rule_name VARCHAR(256) NOT NULL,
                    rule_type VARCHAR(64) NOT NULL,
                    description TEXT NOT NULL,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    thresholds JSONB NOT NULL DEFAULT '{}',
                    cooldown_seconds INTEGER NOT NULL DEFAULT 300,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)

            # Seed default rules
            await self._seed_default_rules(conn)

            logger.info("Anomaly schema initialized")

    async def _seed_default_rules(self, conn: asyncpg.Connection) -> None:
        """Seed default anomaly detection rules."""
        default_rules = [
            AnomalyRule(
                rule_id="failed_auth_spike",
                rule_name="Failed Authentication Spike",
                rule_type=AnomalyRuleType.FAILED_AUTH_SPIKE,
                description="Detects >20 failed login events from a single source IP within 5 minutes",
                thresholds={
                    "threshold": 20,
                    "window_seconds": 300,
                    "action_filter": "deny",
                },
            ),
            AnomalyRule(
                rule_id="unusual_port",
                rule_name="Unusual Destination Port",
                rule_type=AnomalyRuleType.UNUSUAL_PORT,
                description="Flags destination ports not seen in source's historical baseline (last 7 days)",
                thresholds={
                    "baseline_days": 7,
                    "min_occurrences": 3,
                },
            ),
            AnomalyRule(
                rule_id="severity_escalation",
                rule_name="Severity Escalation Cluster",
                rule_type=AnomalyRuleType.SEVERITY_ESCALATION,
                description="Sudden cluster of high/critical severity events from one source within 10 minutes",
                thresholds={
                    "threshold": 5,
                    "window_seconds": 600,
                    "min_severity": "high",
                },
            ),
            AnomalyRule(
                rule_id="protocol_anomaly",
                rule_name="Unexpected Protocol",
                rule_type=AnomalyRuleType.PROTOCOL_ANOMALY,
                description="Unexpected network protocol usage relative to source profile",
                thresholds={
                    "baseline_days": 7,
                },
            ),
            AnomalyRule(
                rule_id="volume_spike",
                rule_name="Event Volume Spike",
                rule_type=AnomalyRuleType.VOLUME_SPIKE,
                description="Unusual spike in total event volume from a source",
                thresholds={
                    "threshold_multiplier": 3.0,
                    "window_seconds": 300,
                    "baseline_window_seconds": 3600,
                },
            ),
        ]

        for rule in default_rules:
            await conn.execute("""
                INSERT INTO anomaly_rules (rule_id, rule_name, rule_type, description, enabled, thresholds, cooldown_seconds)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (rule_id) DO UPDATE SET
                    rule_name = EXCLUDED.rule_name,
                    description = EXCLUDED.description,
                    enabled = EXCLUDED.enabled,
                    thresholds = EXCLUDED.thresholds,
                    cooldown_seconds = EXCLUDED.cooldown_seconds,
                    updated_at = NOW()
            """, rule.rule_id, rule.rule_name, rule.rule_type.value, rule.description,
                rule.enabled, json.dumps(rule.thresholds), rule.cooldown_seconds)

    async def insert_anomaly(self, anomaly: Anomaly) -> Anomaly:
        """Insert a new anomaly."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO anomalies (
                    anomaly_id, event_id, raw_event_id, source_id, source_type,
                    rule_id, rule_name, severity, reason, triggered_fields,
                    detected_at, status
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ON CONFLICT (anomaly_id) DO NOTHING
            """, anomaly.anomaly_id, anomaly.event_id, anomaly.raw_event_id,
                anomaly.source_id, anomaly.source_type, anomaly.rule_id,
                anomaly.rule_name, anomaly.severity.value, anomaly.reason,
                json.dumps(anomaly.triggered_fields), anomaly.detected_at,
                anomaly.status.value)
        return anomaly

    async def get_anomaly(self, anomaly_id: str) -> Anomaly | None:
        """Get anomaly by ID."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM anomalies WHERE anomaly_id = $1", anomaly_id
            )
            if row:
                return self._row_to_anomaly(row)
            return None

    async def list_anomalies(
        self,
        source_id: str | None = None,
        rule_id: str | None = None,
        severity: AnomalySeverity | None = None,
        status: AnomalyStatus | None = None,
        start_time: datetime | str | None = None,
        end_time: datetime | str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[Anomaly], int]:
        """List anomalies with filters and pagination."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            conditions = []
            params: list[Any] = []
            param_idx = 1

            if source_id:
                conditions.append(f"source_id = ${param_idx}")
                params.append(source_id)
                param_idx += 1

            if rule_id:
                conditions.append(f"rule_id = ${param_idx}")
                params.append(rule_id)
                param_idx += 1

            if severity:
                conditions.append(f"severity = ${param_idx}")
                params.append(severity.value)
                param_idx += 1

            if status:
                conditions.append(f"status = ${param_idx}")
                params.append(status.value)
                param_idx += 1

            if start_time:
                conditions.append(f"detected_at >= ${param_idx}")
                if isinstance(start_time, str):
                    params.append(datetime.fromisoformat(start_time.replace("Z", "+00:00")))
                else:
                    params.append(start_time)
                param_idx += 1

            if end_time:
                conditions.append(f"detected_at <= ${param_idx}")
                if isinstance(end_time, str):
                    params.append(datetime.fromisoformat(end_time.replace("Z", "+00:00")))
                else:
                    params.append(end_time)
                param_idx += 1

            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

            # Count total
            count_query = f"SELECT COUNT(*) FROM anomalies {where_clause}"
            total = await conn.fetchval(count_query, *params)

            # Get page
            offset = (page - 1) * page_size
            params.extend([page_size, offset])
            query = f"""
                SELECT * FROM anomalies {where_clause}
                ORDER BY detected_at DESC
                LIMIT ${param_idx} OFFSET ${param_idx + 1}
            """
            rows = await conn.fetch(query, *params)

            anomalies = [self._row_to_anomaly(row) for row in rows]
            return anomalies, total

    async def acknowledge_anomaly(
        self, anomaly_id: str, acknowledged_by: str
    ) -> Anomaly | None:
        """Mark anomaly as acknowledged."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            now = datetime.now(timezone.utc)
            await conn.execute("""
                UPDATE anomalies
                SET status = 'acknowledged', acknowledged_by = $1, acknowledged_at = $2
                WHERE anomaly_id = $3 AND status = 'open'
            """, acknowledged_by, now, anomaly_id)

            row = await conn.fetchrow(
                "SELECT * FROM anomalies WHERE anomaly_id = $1", anomaly_id
            )
            if row:
                return self._row_to_anomaly(row)
            return None

    async def close_anomaly(self, anomaly_id: str) -> Anomaly | None:
        """Mark anomaly as closed."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("""
                UPDATE anomalies SET status = 'closed' WHERE anomaly_id = $1
            """, anomaly_id)

            row = await conn.fetchrow(
                "SELECT * FROM anomalies WHERE anomaly_id = $1", anomaly_id
            )
            if row:
                return self._row_to_anomaly(row)
            return None

    async def clear_all_anomalies(self) -> int:
        """Delete all anomalies from the database.

        Used to reset the dashboard count when simulators are
        started, so each monitoring cycle begins with a clean count.

        Returns:
            Number of rows deleted.
        """
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute("DELETE FROM anomalies")
            # asyncpg returns "DELETE N" string
            try:
                return int(result.split()[-1])
            except (IndexError, ValueError, AttributeError):
                return 0

    async def get_rules(self, enabled_only: bool = False) -> list[AnomalyRule]:
        """Get all anomaly rules."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            query = "SELECT * FROM anomaly_rules"
            if enabled_only:
                query += " WHERE enabled = TRUE"
            query += " ORDER BY created_at"
            rows = await conn.fetch(query)
            return [self._row_to_rule(row) for row in rows]

    async def get_rule(self, rule_id: str) -> AnomalyRule | None:
        """Get rule by ID."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM anomaly_rules WHERE rule_id = $1", rule_id
            )
            if row:
                return self._row_to_rule(row)
            return None

    async def upsert_rule(self, rule: AnomalyRule) -> AnomalyRule:
        """Insert or update a rule."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO anomaly_rules (rule_id, rule_name, rule_type, description, enabled, thresholds, cooldown_seconds)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (rule_id) DO UPDATE SET
                    rule_name = EXCLUDED.rule_name,
                    rule_type = EXCLUDED.rule_type,
                    description = EXCLUDED.description,
                    enabled = EXCLUDED.enabled,
                    thresholds = EXCLUDED.thresholds,
                    cooldown_seconds = EXCLUDED.cooldown_seconds,
                    updated_at = NOW()
            """, rule.rule_id, rule.rule_name, rule.rule_type.value, rule.description,
                rule.enabled, json.dumps(rule.thresholds), rule.cooldown_seconds)
        return rule

    async def get_recent_events_for_source(
        self, source_id: str, since: str, action: str | None = None
    ) -> list[dict[str, Any]]:
        """Get recent normalized events for a source (for baseline calculations)."""
        from ulpf.storage.opensearch_adapter import OpenSearchAdapter

        adapter = OpenSearchAdapter()
        try:
            filters = {"source_ip": source_id}
            if action:
                filters["event_action"] = action

            events, _ = adapter.search(
                filters=filters,
                size=1000,
            )

            # Filter by time if needed (since is ISO format)
            if since:
                from datetime import datetime
                since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
                filtered_events = []
                for event in events:
                    ingestion_ts = event.get("ingestion_timestamp", "")
                    if ingestion_ts:
                        try:
                            event_dt = datetime.fromisoformat(ingestion_ts.replace("Z", "+00:00"))
                            if event_dt >= since_dt:
                                filtered_events.append(event)
                        except (ValueError, TypeError) as exc:
                            logger.debug(
                                "Skipping event with unparseable ingestion_timestamp: %s error=%s",
                                ingestion_ts,
                                exc,
                            )
                return filtered_events

            return events
        finally:
            adapter.close()

    async def get_event_counts_by_source(
        self, since: str, severity: str | None = None
    ) -> dict[str, int]:
        """Get event counts grouped by source for volume spike detection."""
        # Placeholder - would query OpenSearch in real implementation
        return {}

    def _row_to_anomaly(self, row: asyncpg.Record) -> Anomaly:
        return Anomaly(
            anomaly_id=row["anomaly_id"],
            event_id=row["event_id"],
            raw_event_id=row["raw_event_id"],
            source_id=row["source_id"],
            source_type=row["source_type"],
            rule_id=row["rule_id"],
            rule_name=row["rule_name"],
            severity=AnomalySeverity(row["severity"]),
            reason=row["reason"],
            triggered_fields=row["triggered_fields"] or {},
            detected_at=row["detected_at"],
            status=AnomalyStatus(row["status"]),
            acknowledged_by=row["acknowledged_by"],
            acknowledged_at=row["acknowledged_at"],
        )

    def _row_to_rule(self, row: asyncpg.Record) -> AnomalyRule:
        import json
        thresholds = row["thresholds"]
        if isinstance(thresholds, str):
            thresholds = json.loads(thresholds)
        return AnomalyRule(
            rule_id=row["rule_id"],
            rule_name=row["rule_name"],
            rule_type=AnomalyRuleType(row["rule_type"]),
            description=row["description"],
            enabled=row["enabled"],
            thresholds=thresholds or {},
            cooldown_seconds=row["cooldown_seconds"],
            created_at=row["created_at"],
        )