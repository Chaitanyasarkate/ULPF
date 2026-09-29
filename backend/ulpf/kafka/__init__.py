"""ULPF Kafka package.

Provides:
- Topic initialization and management
- Kafka producer service
- Kafka consumer service
"""

from __future__ import annotations

from ulpf.kafka.consumer import UlpfConsumer
from ulpf.kafka.producer import UlpfProducer
from ulpf.kafka.topics import ensure_topics

__all__ = [
    "UlpfConsumer",
    "UlpfProducer",
    "ensure_topics",
]
