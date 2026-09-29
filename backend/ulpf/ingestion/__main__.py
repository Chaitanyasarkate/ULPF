"""Phase 1 ingestion service entry point.

Run with:  python -m ulpf.ingestion

Starts the REST API ingestion service on the configured port.
Also starts the UDP syslog listener for firewall events.
"""

from __future__ import annotations

import logging
import threading

import sys

from ulpf.common.logging import configure_root
from ulpf.common.models import SourceType
from ulpf.config import get_settings
from ulpf.ingestion.kafka_publisher import KafkaPublisher
from ulpf.ingestion.rest import create_app
from ulpf.ingestion.sink import RawEventSink
from ulpf.ingestion.syslog import SyslogListener

log = logging.getLogger("ulpf.ingestion")


def main() -> int:
    configure_root()
    settings = get_settings()

    # Shared sink + publisher so REST and UDP syslog use the same Kafka pipeline.
    shared_sink = RawEventSink()
    shared_publisher = KafkaPublisher()

    app = create_app(
        sink=shared_sink,
        kafka_publisher=shared_publisher,
    )
    port = settings.ingestion.rest_ingest_port
    log.info("Starting ULPF ingestion REST service on port %s", port)

    syslog_listener = SyslogListener(
        sink=shared_sink,
        host=settings.core.app_host,
        udp_port=settings.ingestion.syslog_udp_port,
        source_type=SourceType.FIREWALL.value,
        kafka_publisher=shared_publisher,
    )
    syslog_listener.start()

    try:
        app.run(host=settings.core.app_host, port=port, threaded=True)
    except KeyboardInterrupt:
        log.info("Ingestion service stopped by user")
    finally:
        syslog_listener.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
