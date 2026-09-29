"""OpenSearch adapter for ULPF Phase 5.

Provides searchable storage of normalized events with complete field preservation.

Architecture:
    - OpenSearch stores normalized events for search and analytics
    - Date-based indices for efficient management
    - All OCSF fields, parsed_fields, and provenance preserved

Index structure:
    <prefix>-events-YYYY.MM.DD

Usage:
    adapter = OpenSearchAdapter()
    await adapter.ensure_index()
    await adapter.index_normalized_event(normalized_event)
    results = await adapter.search(query)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("ulpf.storage.opensearch")

try:
    from opensearchpy import OpenSearch

    _OPENSEARCH_AVAILABLE = True
except Exception:  # noqa: BLE001 pragma: no cover - optional dependency guard
    _OPENSEARCH_AVAILABLE = False

from ulpf.common.models import NormalizedEvent
from ulpf.config import get_settings

SearchResult = dict[str, Any]


class OpenSearchError(Exception):
    """Base exception for OpenSearch operations."""


class DocumentNotFoundError(OpenSearchError):
    """Raised when a requested document does not exist."""


class OpenSearchAdapter:
    """OpenSearch adapter for normalized event storage and search.

    Stores normalized events in date-based indices with complete field preservation.
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        use_ssl: bool | None = None,
        verify_certs: bool | None = None,
        index_prefix: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> None:
        if not _OPENSEARCH_AVAILABLE:
            raise RuntimeError("opensearch-py package not installed")

        settings = get_settings()
        host = host or settings.opensearch.host
        self.use_ssl = use_ssl if use_ssl is not None else settings.opensearch.use_ssl
        self.verify_certs = verify_certs if verify_certs is not None else settings.opensearch.verify_certs
        self.index_prefix = index_prefix or settings.opensearch.index_prefix

        if ":" in host:
            host_part, port_part = host.rsplit(":", 1)
            self.host = host_part
            self.port = int(port_part)
        else:
            self.host = host
            self.port = port or 9200

        self.username = username
        self.password = password

        self._client: OpenSearch | None = None

    @property
    def client(self) -> OpenSearch:
        if self._client is None:
            auth = None
            if self.username and self.password:
                auth = (self.username, self.password)

            self._client = OpenSearch(
                hosts=[{"host": self.host, "port": self.port, "scheme": "https" if self.use_ssl else "http"}],
                http_auth=auth,
                verify_certs=self.verify_certs,
                ssl_show_warn=False,
            )
        return self._client

    def close(self) -> None:
        """Close the OpenSearch client connection."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def _get_index_name(self, timestamp: str | None = None) -> str:
        """Generate the index name for a given timestamp.

        Args:
            timestamp: ISO timestamp to extract date from.
                Defaults to current UTC time.

        Returns:
            Index name in format: <prefix>-events-YYYY.MM.DD
        """
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                dt = datetime.now(timezone.utc)
        else:
            dt = datetime.now(timezone.utc)

        date_str = dt.strftime("%Y.%m.%d")
        return f"{self.index_prefix}-events-{date_str}"

    def _build_document(self, event: NormalizedEvent) -> dict[str, Any]:
        """Build the document to index from a NormalizedEvent.

        Preserves all fields including parsed_fields and ocsf for lossless storage.

        Args:
            event: The normalized event to convert.

        Returns:
            Complete document dict for OpenSearch indexing.
        """
        return {
            "event_id": event.event_id,
            "raw_event_id": event.raw_event_id,
            "source_id": event.source_id,
            "source_type": event.source_type,
            "format": event.format,
            "parser_id": event.parser_id,
            "parser_version": event.parser_version,
            "schema_version": event.schema_version,
            "event_timestamp": event.event_timestamp,
            "ingestion_timestamp": event.ingestion_timestamp,
            "sha256": event.sha256,
            "ocsf": event.ocsf,
            "parsed_fields": event.parsed_fields,
            "raw_payload": event.raw_payload,
            "event_action": event.ocsf.get("event", {}).get("action"),
            "event_severity": event.ocsf.get("event", {}).get("severity"),
            "source_ip": event.ocsf.get("source", {}).get("ip"),
            "source_port": event.ocsf.get("source", {}).get("port"),
            "destination_ip": event.ocsf.get("destination", {}).get("ip"),
            "destination_port": event.ocsf.get("destination", {}).get("port"),
            "network_protocol": event.ocsf.get("network", {}).get("protocol"),
            "device_name": event.ocsf.get("device", {}).get("name"),
            "device_type": event.ocsf.get("device", {}).get("type"),
        }

    def _get_index_mapping(self, index_name: str) -> dict[str, Any]:
        """Generate index mapping for normalized events.

        Args:
            index_name: Name of the index.

        Returns:
            Mapping definition for OpenSearch.
        """
        return {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "index.refresh_interval": "5s",
            },
            "mappings": {
                "properties": {
                    "event_id": {"type": "keyword"},
                    "raw_event_id": {"type": "keyword"},
                    "source_id": {"type": "keyword"},
                    "source_type": {"type": "keyword"},
                    "format": {"type": "keyword"},
                    "parser_id": {"type": "keyword"},
                    "parser_version": {"type": "keyword"},
                    "schema_version": {"type": "keyword"},
                    "event_timestamp": {"type": "date"},
                    "ingestion_timestamp": {"type": "date"},
                    "sha256": {"type": "keyword"},
                    "ocsf": {"type": "object", "enabled": True},
                    "parsed_fields": {"type": "object", "enabled": True},
                    "raw_payload": {"type": "text", "index": False},
                    "event_action": {"type": "keyword"},
                    "event_severity": {"type": "keyword"},
                    "source_ip": {"type": "ip", "ignore_malformed": True},
                    "source_port": {"type": "integer"},
                    "destination_ip": {"type": "ip", "ignore_malformed": True},
                    "destination_port": {"type": "integer"},
                    "network_protocol": {"type": "keyword"},
                    "device_name": {"type": "keyword"},
                    "device_type": {"type": "keyword"},
                }
            },
        }

    def ensure_index(self, index_name: str | None = None) -> str:
        """Ensure the index exists, creating it if necessary.

        Args:
            index_name: Optional specific index name. Defaults to current date.

        Returns:
            The index name that was ensured.
        """
        index_name = index_name or self._get_index_name()

        try:
            if not self.client.indices.exists(index=index_name):
                mapping = self._get_index_mapping(index_name)
                self.client.indices.create(index=index_name, body=mapping)
                logger.info("Created OpenSearch index: %s", index_name)
            else:
                logger.debug("OpenSearch index already exists: %s", index_name)

            return index_name

        except Exception as exc:
            logger.error("Failed to ensure index: %s error=%s", index_name, exc)
            raise OpenSearchError(f"Failed to ensure index: {exc}") from exc

    def index_normalized_event(
        self,
        event: NormalizedEvent,
        index_name: str | None = None,
    ) -> str:
        """Index a normalized event.

        Uses event_id as the document ID for deterministic indexing.

        Args:
            event: The normalized event to index.
            index_name: Optional specific index. Defaults to event timestamp date.

        Returns:
            The document ID (event_id).

        Raises:
            OpenSearchError: If indexing fails.
        """
        index_name = index_name or self._get_index_name(event.event_timestamp)

        self.ensure_index(index_name)

        document = self._build_document(event)
        document_id = event.event_id

        try:
            self.client.index(
                index=index_name,
                id=document_id,
                body=document,
                refresh=True,
            )

            logger.info(
                "Indexed normalized event: event_id=%s index=%s",
                event.event_id,
                index_name,
            )

            return document_id

        except Exception as exc:
            logger.error(
                "Failed to index event: event_id=%s error=%s",
                event.event_id,
                exc,
            )
            raise OpenSearchError(f"Failed to index event: {exc}") from exc

    def get_event(self, event_id: str, index_name: str | None = None) -> dict[str, Any] | None:
        """Retrieve a normalized event by event_id.

        Args:
            event_id: The unique event identifier.
            index_name: Optional specific index to search. Searches all if None.

        Returns:
            The event document, or None if not found.
        """
        if index_name:
            try:
                result = self.client.get(index=index_name, id=event_id)
                return result["_source"]
            except Exception:
                return None

        try:
            result = self.client.search(
                index=f"{self.index_prefix}-events-*",
                body={
                    "query": {"term": {"event_id": event_id}},
                    "size": 1,
                },
            )

            hits = result.get("hits", {}).get("hits", [])
            if hits:
                return hits[0]["_source"]
            return None

        except Exception:
            return None

    def search(
        self,
        query: dict[str, Any] | None = None,
        filters: dict[str, Any] | None = None,
        index_pattern: str | None = None,
        size: int = 100,
        from_: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """Search for normalized events.

        Args:
            query: Full OpenSearch query DSL.
            filters: Simple key-value filters to apply.
            index_pattern: Index pattern to search. Defaults to all ulpf indices.
            size: Maximum number of results.
            from_: Offset for pagination.

        Returns:
            Tuple of (list of matching event documents, total count).
        """
        index = index_pattern or f"{self.index_prefix}-events-*"

        if query:
            search_body: dict[str, Any] = {"query": query, "size": size, "from": from_, "track_total_hits": True}
        elif filters:
            must_clauses = []
            for key, value in filters.items():
                must_clauses.append({"term": {key: value}})

            search_body = {
                "query": {"bool": {"must": must_clauses}},
                "size": size,
                "from": from_,
                "track_total_hits": True,
                "sort": [{"ingestion_timestamp": {"order": "desc"}}],
            }
        else:
            search_body = {
                "query": {"match_all": {}},
                "size": size,
                "from": from_,
                "track_total_hits": True,
                "sort": [{"ingestion_timestamp": {"order": "desc"}}],
            }

        try:
            result = self.client.search(index=index, body=search_body)
            hits = result.get("hits", {}).get("hits", [])
            events = [hit["_source"] for hit in hits]
            total = result.get("hits", {}).get("total", {}).get("value", len(events))
            return events, total

        except Exception as exc:
            logger.error("Search failed: error=%s", exc)
            raise OpenSearchError(f"Search failed: {exc}") from exc

    def search_by_field(
        self,
        field: str,
        value: str | int,
        index_pattern: str | None = None,
    ) -> list[dict[str, Any]]:
        """Search for events by a specific field value.

        Args:
            field: Field name to search.
            value: Value to match.
            index_pattern: Optional index pattern.

        Returns:
            List of matching events.
        """
        events, _ = self.search(
            filters={field: value},
            index_pattern=index_pattern,
        )
        return events

    def search_by_time_range(
        self,
        start_time: str,
        end_time: str,
        index_pattern: str | None = None,
        size: int = 1000,
    ) -> list[dict[str, Any]]:
        """Search for events within a time range.

        Args:
            start_time: Start of range (ISO timestamp).
            end_time: End of range (ISO timestamp).
            index_pattern: Optional index pattern.
            size: Maximum results.

        Returns:
            List of events in the time range.
        """
        query = {
            "range": {
                "event_timestamp": {
                    "gte": start_time,
                    "lte": end_time,
                }
            }
        }
        events, _ = self.search(query=query, index_pattern=index_pattern, size=size)
        return events

    def health_check(self) -> bool:
        """Check if OpenSearch is reachable.

        Returns:
            True if OpenSearch is healthy, False otherwise.
        """
        try:
            return self.client.ping()
        except Exception:
            return False

    def get_event_stats(self) -> dict[str, Any]:
        """Get aggregate event statistics using OpenSearch aggregations.

        Returns:
            Dict with total_events, events_by_source, events_by_action,
            events_by_severity, and active_sources counts.
        """
        index = f"{self.index_prefix}-events-*"
        body = {
            "size": 0,
            "track_total_hits": True,
            "aggs": {
                "by_source": {"terms": {"field": "source_type", "size": 100}},
                "by_action": {"terms": {"field": "event_action", "size": 100}},
                "by_severity": {"terms": {"field": "event_severity", "size": 100}},
            },
        }
        try:
            result = self.client.search(index=index, body=body)
            total = result.get("hits", {}).get("total", {}).get("value", 0)
            aggs = result.get("aggregations", {})

            by_source = {
                bucket["key"]: bucket["doc_count"]
                for bucket in aggs.get("by_source", {}).get("buckets", [])
            }
            by_action = {
                bucket["key"]: bucket["doc_count"]
                for bucket in aggs.get("by_action", {}).get("buckets", [])
            }
            by_severity = {
                bucket["key"]: bucket["doc_count"]
                for bucket in aggs.get("by_severity", {}).get("buckets", [])
            }

            return {
                "total_events": total,
                "events_by_source": by_source,
                "events_by_action": by_action,
                "events_by_severity": by_severity,
            }
        except Exception as exc:
            logger.error("Event stats aggregation failed: error=%s", exc)
            raise OpenSearchError(f"Event stats failed: {exc}") from exc

    def get_index_stats(self, index_name: str) -> dict[str, Any] | None:
        """Get statistics for an index.

        Args:
            index_name: Name of the index.

        Returns:
            Index statistics or None if not found.
        """
        try:
            return self.client.indices.stats(index=index_name)
        except Exception:
            return None

    def delete_event(self, event_id: str, index_name: str) -> bool:
        """Delete a normalized event by ID.

        Args:
            event_id: The event identifier.
            index_name: The index containing the event.

        Returns:
            True if deleted, False if not found.
        """
        try:
            self.client.delete(index=index_name, id=event_id, refresh=True)
            logger.info("Deleted event: event_id=%s index=%s", event_id, index_name)
            return True
        except Exception:
            return False

    def clear_all_events(self) -> int:
        """Delete all events from all ulpf event indices.

        Used to reset the dashboard count when simulators are
        started, so each monitoring cycle begins with a clean count.

        Returns:
            Number of indices that were cleared.
        """
        index_pattern = f"{self.index_prefix}-events-*"
        cleared = 0
        try:
            # Find matching indices
            try:
                indices = list(self.client.indices.get(index=index_pattern).keys())
            except Exception:
                indices = []

            for index_name in indices:
                try:
                    self.client.delete_by_query(
                        index=index_name,
                        body={"query": {"match_all": {}}},
                        refresh=True,
                    )
                    cleared += 1
                    logger.info("Cleared all events from index: %s", index_name)
                except Exception as exc:
                    logger.warning("Failed to clear index %s: %s", index_name, exc)

            return cleared
        except Exception as exc:
            logger.error("clear_all_events failed: error=%s", exc)
            return cleared

    def health_check(self) -> bool:
        """Check if OpenSearch cluster is reachable and responsive."""
        if not _OPENSEARCH_AVAILABLE:
            return False
        try:
            return bool(self.client.ping())
        except Exception as exc:
            logger.error("OpenSearch health check failed: %s", exc)
            return False
