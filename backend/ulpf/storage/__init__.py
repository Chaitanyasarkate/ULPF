"""ULPF Phase 5 Storage Layer.

Provides persistent storage adapters for the ULPF pipeline:

- MinIO: Lossless raw event vault (original payloads)
- OpenSearch: Normalized event search and analytics
- PostgreSQL: Metadata, lineage, and storage references

Architecture:
    Kafka raw-logs    -> RawStorageConsumer -> MinIO + PostgreSQL
    Kafka parsed-logs -> (existing parser engine)
    Kafka normalized  -> NormalizedStorageConsumer -> OpenSearch + PostgreSQL

Each storage system has a distinct purpose:
    MinIO: Complete original raw payload
    OpenSearch: Normalized/searchable event
    PostgreSQL: Metadata + lineage + storage references

Usage:
    # Raw event storage
    raw_consumer = RawStorageConsumer()
    raw_consumer.start()

    # Normalized event storage
    norm_consumer = NormalizedStorageConsumer()
    norm_consumer.start()
"""

from __future__ import annotations

from ulpf.storage.minio_adapter import (
    IntegrityVerificationError,
    MinIOAdapter,
    MinIOError,
    ObjectConflictError,
    ObjectNotFoundError,
)
from ulpf.storage.normalized_storage_consumer import NormalizedStorageConsumer
from ulpf.storage.opensearch_adapter import (
    DocumentNotFoundError,
    OpenSearchAdapter,
    OpenSearchError,
)
from ulpf.storage.postgres_adapter import (
    ForeignKeyViolationError,
    PostgresAdapter,
    PostgresError,
    UniqueViolationError,
)
from ulpf.storage.raw_storage_consumer import RawStorageConsumer

__all__ = [
    "DocumentNotFoundError",
    "ForeignKeyViolationError",
    "IntegrityVerificationError",
    "MinIOAdapter",
    "MinIOError",
    "NormalizedStorageConsumer",
    "ObjectConflictError",
    "ObjectNotFoundError",
    "OpenSearchAdapter",
    "OpenSearchError",
    "PostgresAdapter",
    "PostgresError",
    "RawStorageConsumer",
    "UniqueViolationError",
]
