"""Lineage service for ULPF Phase 6.

Provides traceability operations across the event pipeline.

Responsibilities:
- Record lineage relationships
- Retrieve complete lineage chains
- Recover original raw events from MinIO
- Retrieve normalized events from OpenSearch
- Verify lineage integrity
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ulpf.common.models import EventEnvelope
from ulpf.lineage.models import (
    LineageChain,
    LineageVerification,
    RawEventRecovery,
    RelationshipType,
    VerificationStatus,
)
from ulpf.lineage.repository import LineageRepository

logger = logging.getLogger("ulpf.lineage.service")


class LineageService:
    """Service for event lineage and traceability.

    Provides high-level operations for:
    - Recording lineage relationships
    - Retrieving complete lineage chains
    - Recovering original raw events
    - Verifying lineage integrity
    """

    def __init__(
        self,
        lineage_repository: LineageRepository | None = None,
        minio_adapter: Any = None,
        opensearch_adapter: Any = None,
    ) -> None:
        self.lineage_repo = lineage_repository or LineageRepository()

        if minio_adapter:
            self.minio = minio_adapter
        else:
            from ulpf.storage.minio_adapter import MinIOAdapter
            self.minio = MinIOAdapter()

        if opensearch_adapter:
            self.opensearch = opensearch_adapter
        else:
            from ulpf.storage.opensearch_adapter import OpenSearchAdapter
            self.opensearch = OpenSearchAdapter()

    def initialize(self) -> None:
        """Initialize the lineage service.

        Ensures all required schemas exist.
        """
        self.lineage_repo.initialize_schema()
        try:
            import asyncio
            asyncio.run(self.minio.ensure_bucket_exists())
        except Exception as exc:  # noqa: BLE001
            logger.warning("MinIO bucket check failed: %s", exc)

    def record_parsing_lineage(
        self,
        envelope: EventEnvelope,
    ) -> bool:
        """Record lineage for a parsed event.

        Creates: raw_event_id -> parsed_event_id (parsed_from)

        Args:
            envelope: The event envelope with parsed event.

        Returns:
            True if lineage was recorded.
        """
        if envelope.parsed is None:
            logger.warning("No parsed event to record lineage for")
            return False

        success = self.lineage_repo.record_parsed_lineage(envelope)
        if success:
            logger.info(
                "Recorded parse lineage: raw=%s -> parsed=%s",
                envelope.raw.raw_event_id,
                envelope.parsed.event_id,
            )
        return success

    def record_normalization_lineage(
        self,
        envelope: EventEnvelope,
    ) -> bool:
        """Record lineage for a normalized event.

        Creates: parsed_event_id -> normalized_event_id (normalized_from)

        Args:
            envelope: The event envelope with normalized event.

        Returns:
            True if lineage was recorded.
        """
        if envelope.normalized is None:
            logger.warning("No normalized event to record lineage for")
            return False

        success = self.lineage_repo.record_normalized_lineage(envelope)
        if success:
            logger.info(
                "Recorded normalize lineage: parsed=%s -> normalized=%s",
                envelope.parsed.event_id if envelope.parsed else "unknown",
                envelope.normalized.event_id,
            )
        return success

    def get_lineage_chain(self, event_id: str) -> LineageChain | None:
        """Get the complete lineage chain for an event.

        Returns all ancestors (raw, parsed) and descendants (normalized).

        Args:
            event_id: The event ID to get lineage for.

        Returns:
            LineageChain with all ancestors and descendants, or None if not found.
        """
        ancestors = self.lineage_repo.get_ancestors(event_id)
        descendants = self.lineage_repo.get_descendants(event_id)

        if not ancestors and not descendants:
            logger.debug("No lineage found for event: %s", event_id)
            return None

        raw_event_id = ""
        if ancestors:
            raw_event_id = ancestors[0].raw_event_id
        elif descendants:
            raw_event_id = descendants[0].raw_event_id

        chain = LineageChain(
            event_id=event_id,
            raw_event_id=raw_event_id,
            ancestors=ancestors,
            descendants=descendants,
        )

        metadata = self._get_event_metadata(event_id)
        if metadata:
            chain.sha256 = metadata.get("sha256", "")
            chain.parser_id = metadata.get("parser_id", "")
            chain.parser_version = metadata.get("parser_version", "")
            chain.schema_version = metadata.get("schema_version", "")

        return chain

    def get_raw_event_id(self, event_id: str) -> str | None:
        """Get the raw_event_id for any event in the lineage chain.

        Args:
            event_id: Any event ID in the chain.

        Returns:
            The raw_event_id or None if not found.
        """
        if event_id.startswith("raw-"):
            return event_id

        lineage = self.get_lineage_chain(event_id)
        if lineage:
            return lineage.raw_event_id

        metadata = self._get_event_metadata(event_id)
        if metadata:
            return metadata.get("raw_event_id")

        return None

    def recover_raw_event(self, event_id: str) -> RawEventRecovery:
        """Recover the original raw event from MinIO.

        Follows lineage to find the raw_event_id, then retrieves
        the original payload from MinIO.

        Args:
            event_id: Any event ID in the lineage chain.

        Returns:
            RawEventRecovery with the raw payload and verification status.
        """
        raw_event_id = self.get_raw_event_id(event_id)
        if not raw_event_id:
            return RawEventRecovery(
                raw_event_id="",
                sha256="",
                expected_sha256="",
                error="Could not resolve raw_event_id from lineage",
            )

        return self._recover_raw_by_id(raw_event_id)

    def _recover_raw_by_id(self, raw_event_id: str) -> RawEventRecovery:
        """Internal method to recover raw event by raw_event_id."""
        import asyncio

        from ulpf.storage.postgres_adapter import PostgresAdapter

        pg = PostgresAdapter()
        raw_ref = asyncio.run(pg.get_raw_object_reference(raw_event_id))

        if not raw_ref:
            return RawEventRecovery(
                raw_event_id=raw_event_id,
                sha256="",
                expected_sha256="",
                error="No MinIO reference found in PostgreSQL",
            )

        expected_sha256 = raw_ref.get("sha256", "")
        object_key = raw_ref.get("object_key", "")
        bucket = raw_ref.get("bucket", "")

        if not object_key:
            return RawEventRecovery(
                raw_event_id=raw_event_id,
                sha256="",
                expected_sha256=expected_sha256,
                object_key=object_key,
                bucket=bucket,
                error="No object key in reference",
            )

        raw_bytes = asyncio.run(self.minio._get_object_content(object_key))

        if raw_bytes is None:
            return RawEventRecovery(
                raw_event_id=raw_event_id,
                sha256="",
                expected_sha256=expected_sha256,
                object_key=object_key,
                bucket=bucket,
                exists=False,
                error="Object not found in MinIO",
            )

        try:
            raw_obj = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return RawEventRecovery(
                raw_event_id=raw_event_id,
                sha256="",
                expected_sha256=expected_sha256,
                object_key=object_key,
                bucket=bucket,
                exists=True,
                verified=False,
                error=f"Object content corrupt (integrity check failed): {exc}",
            )

        raw_payload = raw_obj.get("payload", "")
        actual_sha256 = raw_obj.get("sha256", "")

        verified = actual_sha256 == expected_sha256

        return RawEventRecovery(
            raw_event_id=raw_event_id,
            sha256=actual_sha256,
            expected_sha256=expected_sha256,
            raw_payload=raw_payload,
            object_key=object_key,
            bucket=bucket,
            exists=True,
            verified=verified,
        )

    def get_normalized_event(
        self,
        event_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve a normalized event from OpenSearch.

        Args:
            event_id: The normalized event ID.

        Returns:
            The normalized event document or None if not found.
        """
        try:
            return self.opensearch.get_event(event_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to get normalized event: event_id=%s error=%s", event_id, exc)
            return None

    def get_events_by_raw_id(self, raw_event_id: str) -> dict[str, Any]:
        """Get all events related to a raw event.

        Returns parsed and normalized events associated with the raw event.

        Args:
            raw_event_id: The raw event ID.

        Returns:
            Dict with 'parsed' and 'normalized' events if found.
        """
        lineage_records = self.lineage_repo.get_lineage_by_raw_id(raw_event_id)

        result: dict[str, Any] = {
            "raw_event_id": raw_event_id,
            "parsed": None,
            "normalized": None,
            "lineage_records": [r.to_dict() for r in lineage_records],
        }

        for record in lineage_records:
            if record.relationship_type == RelationshipType.PARSED_FROM:
                result["parsed"] = self._get_event_metadata(record.child_event_id)
            elif record.relationship_type == RelationshipType.NORMALIZED_FROM:
                result["normalized"] = self.get_normalized_event(record.child_event_id)

        return result

    def verify_lineage(self, event_id: str) -> LineageVerification:
        """Verify the complete lineage for an event.

        Checks:
        - Raw event exists in MinIO
        - SHA-256 matches
        - Normalized event exists in OpenSearch
        - Lineage chain is complete

        Args:
            event_id: The event ID to verify.

        Returns:
            LineageVerification with detailed results.
        """
        verification = LineageVerification(
            event_id=event_id,
            raw_event_id="",
        )
        errors: list[str] = []

        lineage = self.get_lineage_chain(event_id)
        if lineage:
            verification.lineage_chain = lineage
            verification.raw_event_id = lineage.raw_event_id

        raw_recovery = self.recover_raw_event(event_id)
        verification.raw_object_exists = raw_recovery.exists
        verification.sha256_verified = raw_recovery.verified
        verification.raw_payload = raw_recovery.raw_payload

        if raw_recovery.error:
            errors.append(raw_recovery.error)

        # Resolve the normalized event's own event_id from the lineage chain
        # instead of reusing the parsed event_id for the OpenSearch lookup.
        normalized_event_id = event_id
        if lineage and lineage.descendants:
            for desc in lineage.descendants:
                if desc.relationship_type == RelationshipType.NORMALIZED_FROM:
                    normalized_event_id = desc.child_event_id
                    break
        elif lineage and lineage.ancestors:
            for anc in lineage.ancestors:
                if anc.relationship_type == RelationshipType.NORMALIZED_FROM:
                    normalized_event_id = anc.child_event_id
                    break

        normalized = self.get_normalized_event(normalized_event_id)
        verification.normalized_object_exists = normalized is not None

        if not normalized:
            errors.append("Normalized event not found in OpenSearch")

        verification.lineage_complete = bool(
            lineage and
            raw_recovery.exists and
            raw_recovery.verified and
            normalized is not None
        )

        if verification.lineage_complete:
            verification.status = VerificationStatus.VALID
        elif errors:
            verification.status = VerificationStatus.UNAVAILABLE
        else:
            verification.status = VerificationStatus.INVALID

        verification.errors = errors
        return verification

    def _get_event_metadata(self, event_id: str) -> dict[str, Any] | None:
        """Get event metadata from PostgreSQL."""
        import asyncio
        from ulpf.storage.postgres_adapter import PostgresAdapter

        try:
            pg = PostgresAdapter()
            return asyncio.run(pg.get_event_metadata(event_id))
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to get event metadata: event_id=%s error=%s", event_id, exc)
            return None

    def health_check(self) -> dict[str, bool]:
        """Check health of lineage dependencies.

        Returns:
            Dict with health status of each dependency.
        """
        import asyncio

        health = {
            "lineage_repository": False,
            "minio": False,
            "opensearch": False,
        }

        try:
            from ulpf.storage.postgres_adapter import PostgresAdapter
            pg = PostgresAdapter()
            health["lineage_repository"] = bool(asyncio.run(pg.health_check()))
        except Exception as exc:  # noqa: BLE001
            logger.error("Lineage repository health check failed: %s", exc)

        try:
            minio_check = self.minio.health_check()
            health["minio"] = bool(asyncio.run(minio_check) if asyncio.iscoroutine(minio_check) else minio_check)
        except Exception as exc:  # noqa: BLE001
            logger.error("MinIO health check failed: %s", exc)

        try:
            os_check = self.opensearch.health_check()
            health["opensearch"] = bool(asyncio.run(os_check) if asyncio.iscoroutine(os_check) else os_check)
        except Exception as exc:  # noqa: BLE001
            logger.error("OpenSearch health check failed: %s", exc)

        return health
