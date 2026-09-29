"""Unit tests for the centralized configuration layer."""

from __future__ import annotations

from ulpf import config as config_module


def test_default_core_settings():
    settings = config_module.get_settings()
    assert settings.core.env == "test"
    assert settings.core.app_port == 5000
    assert settings.core.log_level == "DEBUG"


def test_kafka_topics_configurable(monkeypatch):
    monkeypatch.setenv("KAFKA_TOPIC_RAW_LOGS", "custom-raw")
    settings = config_module.get_settings()
    assert settings.kafka.topic_raw_logs == "custom-raw"
    assert "custom-raw" in settings.kafka.topics()


def test_minio_config_defaults():
    settings = config_module.get_settings()
    assert settings.minio.secure is False
    assert settings.minio.bucket == "ulpf-raw-events"


def test_security_jwt_default_is_insecure_in_dev(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    settings = config_module.get_settings()
    assert settings.security.jwt_secret_key == "dev-insecure-jwt-secret-change-me"


def test_security_jwt_from_env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "super-secret-value")
    settings = config_module.get_settings()
    assert settings.security.jwt_secret_key == "super-secret-value"


def test_ai_disabled_by_default():
    settings = config_module.get_settings()
    assert settings.ai.enabled is False


def test_get_settings_returns_independent_instances():
    a = config_module.get_settings()
    b = config_module.get_settings()
    assert a is not b
    assert a.kafka.topics() == b.kafka.topics()
