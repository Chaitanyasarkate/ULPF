"""
ULPF foundation entry point.

Run with:  python -m ulpf

This is a *Phase 0* verification entrypoint. It validates that the
configuration layer, core data model, and hashing foundation load and operate
correctly, then prints a startup banner summarising the active settings.

It is NOT a placeholder for future phases — it provides a real, runnable
health check that the backend image builds and the config layer is wired.
Phase 1+ replaces this default command with the actual ingestion/service
entrypoints (each registered under its own module).
"""

from __future__ import annotations

import sys

from ulpf import config as config_module
from ulpf.common.hashing import compute_event_hash, verify_event_hash
from ulpf.common.logging import get_logger
from ulpf.common.models import SCHEMA_VERSION, EventEnvelope

log = get_logger("ulpf")


def _self_test() -> bool:
    envelope = EventEnvelope.from_raw("selftest payload", source_id="selftest", fmt="json")
    fingerprint = compute_event_hash(envelope.raw.to_dict())
    if not verify_event_hash(envelope.raw.to_dict(), fingerprint):
        log.error("Self-test FAILED: hash verification mismatch")
        return False
    if envelope.raw_event_id != envelope.raw.raw_event_id:
        log.error("Self-test FAILED: event id mismatch")
        return False
    log.info("Self-test passed (schema_version=%s)", SCHEMA_VERSION)
    return True


def main() -> int:
    settings = config_module.get_settings()
    log.info("ULPF foundation starting (env=%s, log_level=%s)", settings.core.env, settings.core.log_level)
    log.info(
        "Kafka=%s | topics=%s",
        settings.kafka.bootstrap_servers,
        settings.kafka.topics(),
    )
    log.info("MinIO bucket=%s | OpenSearch host=%s | Postgres db=%s", settings.minio.bucket, settings.opensearch.host, settings.postgres.db)
    if not _self_test():
        return 1
    log.info("ULPF foundation ready. Awaiting service entrypoints (added in later phases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
