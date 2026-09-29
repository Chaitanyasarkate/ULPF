"""
Centralized application configuration for ULPF.

All runtime settings are sourced from environment variables (12-factor app
style). A `.env` file is optionally loaded in development via python-dotenv,
but production deployments (including air-gapped installs) rely purely on the
process environment so that no secrets live in the repository.

The configuration object is intentionally dependency-free (stdlib only) so it
can be imported by every service without pulling in heavy dependencies.

Each setting is read from ``os.environ`` lazily via ``field(default_factory=...)``
so that a freshly constructed ``Settings`` instance always reflects the current
process environment. This keeps behaviour deterministic for tests (env overrides
take effect immediately) and correct for runtime reconfiguration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _load_dotenv() -> None:
    """Best-effort load of a .env file for local development only."""
    try:
        from dotenv import find_dotenv, load_dotenv  # type: ignore

        env_path = find_dotenv(usecwd=True)
        if env_path:
            load_dotenv(env_path)
        else:
            load_dotenv()
    except Exception:
        pass


_load_dotenv()


def _get(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _get_int(key: str, default: int) -> int:
    raw = os.environ.get(key)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _get_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class CoreConfig:
    env: str = field(default_factory=lambda: _get("ULPF_ENV", "development"))
    app_host: str = field(default_factory=lambda: _get("ULPF_APP_HOST", "0.0.0.0"))
    app_port: int = field(default_factory=lambda: _get_int("ULPF_APP_PORT", 5000))
    log_level: str = field(default_factory=lambda: _get("ULPF_LOG_LEVEL", "INFO").upper())


@dataclass(frozen=True)
class KafkaConfig:
    bootstrap_servers: str = field(default_factory=lambda: _get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"))
    topic_raw_logs: str = field(default_factory=lambda: _get("KAFKA_TOPIC_RAW_LOGS", "raw-logs"))
    topic_parsed_logs: str = field(default_factory=lambda: _get("KAFKA_TOPIC_PARSED_LOGS", "parsed-logs"))
    topic_normalized: str = field(default_factory=lambda: _get("KAFKA_TOPIC_NORMALIZED_EVENTS", "normalized-events"))
    topic_failed: str = field(default_factory=lambda: _get("KAFKA_TOPIC_FAILED_EVENTS", "failed-events"))
    topic_schema_drift: str = field(default_factory=lambda: _get("KAFKA_TOPIC_SCHEMA_DRIFT", "schema-drift-events"))
    group_id: str = field(default_factory=lambda: _get("KAFKA_GROUP_ID", "ulpf-processing"))
    auto_offset_reset: str = field(default_factory=lambda: _get("KAFKA_AUTO_OFFSET_RESET", "latest"))
    enabled: bool = field(default_factory=lambda: _get_bool("ULPF_KAFKA_ENABLED", False))

    def topics(self) -> list[str]:
        return [
            self.topic_raw_logs,
            self.topic_parsed_logs,
            self.topic_normalized,
            self.topic_failed,
            self.topic_schema_drift,
        ]


@dataclass(frozen=True)
class MinIOConfig:
    endpoint: str = field(default_factory=lambda: _get("MINIO_ENDPOINT", "localhost:9000"))
    access_key: str = field(default_factory=lambda: _get("MINIO_ROOT_USER", "minioadmin"))
    secret_key: str = field(default_factory=lambda: _get("MINIO_ROOT_PASSWORD", "minioadmin"))
    bucket: str = field(default_factory=lambda: _get("MINIO_RAW_BUCKET", "ulpf-raw-events"))
    secure: bool = field(default_factory=lambda: _get_bool("MINIO_SECURE", False))


@dataclass(frozen=True)
class OpenSearchConfig:
    host: str = field(default_factory=lambda: _get("OPENSEARCH_HOST", "localhost:9200"))
    use_ssl: bool = field(default_factory=lambda: _get_bool("OPENSEARCH_USE_SSL", False))
    verify_certs: bool = field(default_factory=lambda: _get_bool("OPENSEARCH_VERIFY_CERTS", False))
    index_prefix: str = field(default_factory=lambda: _get("OPENSEARCH_INDEX_PREFIX", "ulpf"))
    ssl_show_warn: bool = field(default_factory=lambda: _get_bool("OPENSEARCH_SSL_SHOW_WARN", False))


@dataclass(frozen=True)
class PostgresConfig:
    host: str = field(default_factory=lambda: _get("POSTGRES_HOST", "localhost"))
    port: int = field(default_factory=lambda: _get_int("POSTGRES_PORT", 5432))
    db: str = field(default_factory=lambda: _get("POSTGRES_DB", "ulpf"))
    user: str = field(default_factory=lambda: _get("POSTGRES_USER", "ulpf"))
    password: str = field(default_factory=lambda: _get("POSTGRES_PASSWORD", ""))
    min_pool: int = field(default_factory=lambda: _get_int("POSTGRES_MIN_POOL", 2))
    max_pool: int = field(default_factory=lambda: _get_int("POSTGRES_MAX_POOL", 10))


@dataclass(frozen=True)
class SecurityConfig:
    jwt_secret_key: str = field(default_factory=lambda: _get("JWT_SECRET_KEY") or "dev-insecure-jwt-secret-change-me")
    jwt_algorithm: str = field(default_factory=lambda: _get("JWT_ALGORITHM", "HS256"))
    jwt_access_expires_hours: int = field(default_factory=lambda: _get_int("JWT_ACCESS_TOKEN_EXPIRES_HOURS", 8))
    jwt_refresh_expires_days: int = field(default_factory=lambda: _get_int("JWT_REFRESH_TOKEN_EXPIRES_DAYS", 30))
    password_hash_scheme: str = field(default_factory=lambda: _get("PASSWORD_HASH_SCHEME", "bcrypt"))
    hash_algorithm: str = field(default_factory=lambda: _get("HASH_ALGORITHM", "sha256"))
    lineage_hash_seed: str = field(default_factory=lambda: _get("LINEAGE_HASH_SEED", ""))
    # Lightweight local/demo user bootstrap. Passwords are hashed with bcrypt at
    # startup and never stored in plaintext. Documented demo credentials live in
    # .env.example; production deployments should supply these via secrets.
    demo_admin_username: str = field(default_factory=lambda: _get("ULPF_DEMO_ADMIN_USERNAME", "admin"))
    demo_admin_password: str = field(default_factory=lambda: _get("ULPF_DEMO_ADMIN_PASSWORD", "ulpf-admin-demo"))
    demo_analyst_username: str = field(default_factory=lambda: _get("ULPF_DEMO_ANALYST_USERNAME", "analyst"))
    demo_analyst_password: str = field(default_factory=lambda: _get("ULPF_DEMO_ANALYST_PASSWORD", "ulpf-analyst-demo"))
    demo_viewer_username: str = field(default_factory=lambda: _get("ULPF_DEMO_VIEWER_USERNAME", "viewer"))
    demo_viewer_password: str = field(default_factory=lambda: _get("ULPF_DEMO_VIEWER_PASSWORD", "ulpf-viewer-demo"))
    auth_enabled: bool = field(default_factory=lambda: _get_bool("ULPF_AUTH_ENABLED", False))


@dataclass(frozen=True)
class TLSConfig:
    """TLS/mTLS configuration for the ULPF API and ingestion services.

    When ``enabled`` is true, both ``cert_file`` and ``key_file`` must point to
    readable PEM files. ``ca_file`` is optional and enables client certificate
    (mTLS) verification when set. ``min_version`` controls the minimum TLS
    protocol version (default TLSv1.2).
    """

    enabled: bool = field(default_factory=lambda: _get_bool("ULPF_TLS_ENABLED", False))
    cert_file: str = field(default_factory=lambda: _get("ULPF_TLS_CERT_FILE", ""))
    key_file: str = field(default_factory=lambda: _get("ULPF_TLS_KEY_FILE", ""))
    ca_file: str = field(default_factory=lambda: _get("ULPF_TLS_CA_FILE", ""))
    min_version: str = field(default_factory=lambda: _get("ULPF_TLS_MIN_VERSION", "TLSv1.2"))


@dataclass(frozen=True)
class IngestionConfig:
    syslog_udp_port: int = field(default_factory=lambda: _get_int("SYSLOG_UDP_PORT", 5514))
    syslog_tcp_port: int = field(default_factory=lambda: _get_int("SYSLOG_TCP_PORT", 514))
    rest_ingest_port: int = field(default_factory=lambda: _get_int("REST_INGEST_PORT", 8000))


@dataclass(frozen=True)
class AIConfig:
    """AI-assisted parser generator configuration.

    The default provider ``heuristic`` is a fully local, deterministic,
    rule-assisted implementation that works in air-gapped environments. An
    external provider (e.g. ``openai``) is optional and never required for the
    core pipeline.
    """

    enabled: bool = field(default_factory=lambda: _get_bool("AI_PARSER_ENABLED", True))
    provider: str = field(default_factory=lambda: _get("AI_PROVIDER", "heuristic"))
    model: str = field(default_factory=lambda: _get("AI_MODEL", "heuristic-local-v1"))
    base_url: str = field(default_factory=lambda: _get("AI_BASE_URL", ""))
    api_key: str = field(default_factory=lambda: _get("AI_API_KEY", ""))


@dataclass(frozen=True)
class Settings:
    core: CoreConfig = field(default_factory=CoreConfig)
    kafka: KafkaConfig = field(default_factory=KafkaConfig)
    minio: MinIOConfig = field(default_factory=MinIOConfig)
    opensearch: OpenSearchConfig = field(default_factory=OpenSearchConfig)
    postgres: PostgresConfig = field(default_factory=PostgresConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    ingestion: IngestionConfig = field(default_factory=IngestionConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    tls: TLSConfig = field(default_factory=TLSConfig)
    parsers_dir: str = field(default_factory=lambda: _get("ULPF_PARSERS_DIR", "/app/parsers"))
    samples_dir: str = field(default_factory=lambda: _get("ULPF_SAMPLES_DIR", "/app/sample_logs"))


settings = Settings()


def get_settings() -> Settings:
    """Build a fresh ``Settings`` instance, re-reading the current process
    environment. Tests may override env vars and call this to observe them."""
    return Settings()
