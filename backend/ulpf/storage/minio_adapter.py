"""MinIO (S3-compatible) raw event vault adapter for ULPF Phase 9B.

Provides lossless storage of original raw event payloads with SHA-256
integrity verification.

Architecture:
    - MinIO stores the COMPLETE original raw payload without modification
    - Object keys are deterministic based on raw_event_id
    - SHA-256 verification ensures payload integrity

Object key structure:
    raw-events/<date>/<source_type>/<raw_event_id>.json

Usage:
    adapter = MinIOAdapter()
    await adapter.upload_envelope(envelope)
    raw_payload = await adapter.get_raw_payload(raw_event_id)
    verified = await adapter.verify_integrity(raw_event_id, expected_sha256)
"""

from __future__ import annotations

import io
import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("ulpf.storage.minio")

try:
    from minio import Minio
    from minio.error import S3Error

    _MINIO_AVAILABLE = True
except Exception:  # noqa: BLE001 pragma: no cover - optional dependency guard
    _MINIO_AVAILABLE = False
    S3Error = Exception

from ulpf.common.models import EventEnvelope
from ulpf.config import get_settings

RawObjectMetadata = dict[str, Any]


class MinIOError(Exception):
    """Base exception for MinIO storage operations."""


class ObjectConflictError(MinIOError):
    """Raised when an object with different content already exists."""


class ObjectNotFoundError(MinIOError):
    """Raised when a requested object does not exist."""


class IntegrityVerificationError(MinIOError):
    """Raised when SHA-256 verification fails."""


class MinIOAdapter:
    """MinIO/S3-compatible adapter for raw event vault storage.

    Stores original raw event payloads losslessly with deterministic
    object keys and SHA-256 integrity verification.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        bucket: str | None = None,
        secure: bool | None = None,
    ) -> None:
        if not _MINIO_AVAILABLE:
            raise RuntimeError("minio package not installed")

        settings = get_settings()
        self.endpoint = endpoint or settings.minio.endpoint
        self.access_key = access_key or settings.minio.access_key
        self.secret_key = secret_key or settings.minio.secret_key
        self.bucket = bucket or settings.minio.bucket
        self.secure = secure if secure is not None else settings.minio.secure

        self._client: Any = None

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = Minio(
                self.endpoint,
                access_key=self.access_key,
                secret_key=self.secret_key,
                secure=self.secure,
            )
        return self._client

    def _generate_object_key(
        self,
        raw_event_id: str,
        source_type: str,
        received_at: str | None = None,
    ) -> str:
        """Generate a deterministic object key for a raw event.

        Structure: raw-events/<date>/<source_type>/<raw_event_id>.json

        Args:
            raw_event_id: Unique identifier for the raw event.
            source_type: Type of the log source (e.g., firewall, router).
            received_at: ISO timestamp of when the event was received.

        Returns:
            Deterministic S3 object key.
        """
        if received_at:
            try:
                dt = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
            except ValueError:
                dt = datetime.now(timezone.utc)
        else:
            dt = datetime.now(timezone.utc)

        date_str = dt.strftime("%Y/%m/%d")
        safe_source_type = source_type or "unknown"
        return f"raw-events/{date_str}/{safe_source_type}/{raw_event_id}.json"

    def _build_object_metadata(
        self,
        envelope: EventEnvelope,
        object_key: str,
    ) -> dict[str, str]:
        """Build metadata dict for a stored raw event object.

        Args:
            envelope: The event envelope being stored.
            object_key: The S3 object key.

        Returns:
            Metadata dict for the object.
        """
        return {
            "raw_event_id": envelope.raw.raw_event_id,
            "event_id": envelope.event_id,
            "source_id": envelope.raw.source_id,
            "source_type": envelope.raw.source_type,
            "format": envelope.raw.format,
            "ingestion_timestamp": envelope.raw.received_at,
            "sha256": envelope.sha256,
        }

    def _build_object_content(self, envelope: EventEnvelope) -> bytes:
        """Build the JSON content for a raw event object.

        Stores the complete original raw event with all metadata.

        Args:
            envelope: The event envelope to store.

        Returns:
            JSON-encoded bytes of the complete raw event.
        """
        content = {
            "raw_event_id": envelope.raw.raw_event_id,
            "source_id": envelope.raw.source_id,
            "source_type": envelope.raw.source_type,
            "format": envelope.raw.format,
            "received_at": envelope.raw.received_at,
            "payload": envelope.raw.payload,
            "original_payload_bytes": envelope.raw.original_payload_bytes,
            "sha256": envelope.sha256,
        }
        return json.dumps(content, sort_keys=False).encode("utf-8")

    async def ensure_bucket_exists(self) -> None:
        """Ensure the configured bucket exists, creating it if necessary."""
        try:
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
                logger.info("Created MinIO bucket: %s", self.bucket)
            else:
                logger.debug("MinIO bucket already exists: %s", self.bucket)
        except S3Error as exc:
            logger.error("Failed to ensure bucket exists: %s", exc)
            raise MinIOError(f"Failed to ensure bucket exists: {exc}") from exc

    async def upload_envelope(
        self,
        envelope: EventEnvelope,
        skip_if_exists: bool = False,
    ) -> str:
        """Store a raw event envelope in MinIO.

        Args:
            envelope: The event envelope containing the raw event to store.
            skip_if_exists: If True, skip upload if object already exists.
                If False (default), verify content matches and raise on conflict.

        Returns:
            The object key where the event was stored.

        Raises:
            ObjectConflictError: If skip_if_exists=False and content differs.
        """
        object_key = self._generate_object_key(
            envelope.raw.raw_event_id,
            envelope.raw.source_type,
            envelope.raw.received_at,
        )

        content = self._build_object_content(envelope)
        metadata = self._build_object_metadata(envelope, object_key)

        try:
            existing = await self.exists(envelope.raw.raw_event_id)

            if existing:
                if skip_if_exists:
                    logger.debug(
                        "Object already exists, skipping: %s",
                        object_key,
                    )
                    return object_key

                existing_obj = await self._get_object_content(object_key)
                if existing_obj:
                    try:
                        existing_data = json.loads(existing_obj.decode("utf-8"))
                    except json.JSONDecodeError:
                        pass
                    else:
                        if existing_data.get("sha256") == envelope.sha256:
                            logger.debug(
                                "Object with matching hash exists: %s",
                                object_key,
                            )
                            return object_key

                raise ObjectConflictError(
                    f"Object with different content already exists: {object_key}"
                )

            self.client.put_object(
                self.bucket,
                object_key,
                data=io.BytesIO(content),
                length=len(content),
                content_type="application/json",
                metadata=metadata,
            )

            logger.info(
                "Stored raw event: raw_event_id=%s bucket=%s key=%s size=%d",
                envelope.raw.raw_event_id,
                self.bucket,
                object_key,
                len(content),
            )

            return object_key

        except S3Error as exc:
            logger.error(
                "Failed to upload raw event: raw_event_id=%s error=%s",
                envelope.raw.raw_event_id,
                exc,
            )
            raise MinIOError(f"Failed to upload raw event: {exc}") from exc

    async def _get_object_content(self, object_key: str) -> bytes | None:
        """Get raw content of an object.

        Args:
            object_key: The S3 object key.

        Returns:
            Raw bytes of the object, or None if not found.
        """
        try:
            response = self.client.get_object(self.bucket, object_key)
            content = response.read()
            response.close()
            response.release_conn()
            return content
        except S3Error:
            return None

    async def get_raw_payload(self, raw_event_id: str) -> str | None:
        """Retrieve the original raw payload by raw_event_id.

        Note: This searches for objects by raw_event_id in the key.
        For production, use get_by_object_key() with stored metadata.

        Args:
            raw_event_id: The unique identifier of the raw event.

        Returns:
            The original raw payload string, or None if not found.
        """
        try:
            response = self.client.get_object(
                self.bucket,
                f"raw-events/*/*/{raw_event_id}.json",
            )
            content = response.read()
            response.close()
            response.release_conn()

            data = json.loads(content.decode("utf-8"))
            return data.get("payload")

        except S3Error:
            return None

    async def get_by_object_key(self, object_key: str) -> dict[str, Any] | None:
        """Retrieve a raw event by its object key.

        Args:
            object_key: The full S3 object key.

        Returns:
            The stored raw event dict, or None if not found.
        """
        try:
            response = self.client.get_object(self.bucket, object_key)
            content = response.read()
            response.close()
            response.release_conn()
            try:
                return json.loads(content.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                logger.warning(
                    "Object %s exists but content is not valid JSON/UTF-8: %s",
                    object_key, exc,
                )
                return None
        except S3Error:
            return None

    async def exists(self, raw_event_id: str) -> bool:
        """Check if a raw event exists in the vault.

        Uses prefix search to find objects matching the raw_event_id.

        Args:
            raw_event_id: The unique identifier of the raw event.

        Returns:
            True if the object exists, False otherwise.
        """
        prefix = "raw-events/"
        try:
            objects = self.client.list_objects(
                self.bucket,
                prefix=prefix,
                recursive=True,
            )
            for obj in objects:
                if raw_event_id in obj.object_name:
                    return True
            return False
        except S3Error:
            return False

    async def verify_integrity(
        self,
        raw_event_id: str,
        expected_sha256: str,
    ) -> tuple[bool, str | None]:
        """Verify the SHA-256 integrity of a stored raw event.

        Args:
            raw_event_id: The unique identifier of the raw event.
            expected_sha256: The expected SHA-256 hash.

        Returns:
            Tuple of (verified: bool, actual_sha256: str | None).
            If verified is True, the integrity check passed.
            If verified is False, actual_sha256 contains the computed hash.
        """
        try:
            prefix = "raw-events/"
            objects = self.client.list_objects(
                self.bucket,
                prefix=prefix,
                recursive=True,
            )
            object_key = None
            for obj in objects:
                if raw_event_id in obj.object_name:
                    object_key = obj.object_name
                    break

            if not object_key:
                return False, None

            response = self.client.get_object(self.bucket, object_key)
            content = response.read()
            response.close()
            response.release_conn()

            from ulpf.common.hashing import sha256_hex

            stored_data = json.loads(content.decode("utf-8"))
            payload = stored_data.get("payload", "")
            actual_sha256 = sha256_hex(payload.encode("utf-8"))

            return actual_sha256 == expected_sha256, actual_sha256

        except S3Error:
            return False, None

    async def health_check(self) -> bool:
        """Check if MinIO is reachable.

        Returns:
            True if MinIO is healthy, False otherwise.
        """
        try:
            self.client.bucket_exists(self.bucket)
            return True
        except S3Error:
            return False

    async def delete(self, raw_event_id: str) -> bool:
        """Delete a raw event from the vault.

        Args:
            raw_event_id: The unique identifier of the raw event to delete.

        Returns:
            True if deleted, False if not found.
        """
        try:
            prefix = "raw-events/"
            objects = self.client.list_objects(
                self.bucket,
                prefix=prefix,
                recursive=True,
            )
            for obj in objects:
                if raw_event_id in obj.object_name:
                    self.client.remove_object(self.bucket, obj.object_name)
                    logger.info(
                        "Deleted raw event: raw_event_id=%s key=%s",
                        raw_event_id,
                        obj.object_name,
                    )
                    return True
            return False
        except S3Error:
            return False
