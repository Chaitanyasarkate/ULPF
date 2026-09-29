"""Kafka topic management for ULPF."""

from __future__ import annotations

import logging

from ulpf.config import get_settings

logger = logging.getLogger("ulpf.kafka.topics")

try:
    from kafka.admin import KafkaAdminClient, NewTopic

    _KAFKA_ADMIN_AVAILABLE = True
except Exception:  # noqa: BLE001  # pragma: no cover - optional dependency guard
    _KAFKA_ADMIN_AVAILABLE = False


def ensure_topics(topic_names: list[str] | None = None) -> list[str]:
    """Create ULPF Kafka topics if they do not already exist.

    Args:
        topic_names: Optional list of topic names. Defaults to all configured
            ULPF topics from ``KafkaConfig``.

    Returns:
        The list of topic names that were ensured to exist.
    """
    if not _KAFKA_ADMIN_AVAILABLE:
        logger.warning("kafka-python admin client not available; skipping topic creation")
        return topic_names or []

    settings = get_settings()
    topic_names = topic_names or settings.kafka.topics()
    if not topic_names:
        return []

    admin_client = None
    try:
        admin_client = KafkaAdminClient(
            bootstrap_servers=settings.kafka.bootstrap_servers,
            client_id="ulpf-topic-init",
            request_timeout_ms=10000,
        )
        existing = set(admin_client.list_topics())
        new_topics = []
        for name in topic_names:
            if name not in existing:
                new_topics.append(NewTopic(name=name, num_partitions=1, replication_factor=1))

        if new_topics:
            admin_client.create_topics(new_topics, timeout_ms=30000)
            logger.info("Created Kafka topics: %s", [t.name for t in new_topics])
        else:
            logger.debug("All Kafka topics already exist: %s", topic_names)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Topic initialization failed: %s", exc)
    finally:
        if admin_client is not None:
            try:
                admin_client.close()
            except Exception:  # noqa: BLE001,S110
                pass

    return topic_names
