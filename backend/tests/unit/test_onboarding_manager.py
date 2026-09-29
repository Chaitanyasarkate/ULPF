"""Unit tests for source onboarding manager."""

from __future__ import annotations

from unittest.mock import MagicMock

from ulpf.onboarding.manager import SourceOnboardingManager, ValidationError
from ulpf.onboarding.models import SourceProfile


class TestSourceOnboardingManager:
    def test_validate_valid_profile(self):
        mock_repo = MagicMock()
        manager = SourceOnboardingManager(source_repository=mock_repo)

        profile = SourceProfile(
            source_id="firewall.test",
            source_name="Test Firewall",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
        )

        errors = manager.validate_profile(profile)
        assert len(errors) == 0

    def test_validate_missing_source_id(self):
        mock_repo = MagicMock()
        manager = SourceOnboardingManager(source_repository=mock_repo)

        profile = SourceProfile(
            source_id="",
            source_name="Test",
            source_type="firewall",
            format="syslog",
            parser_id="test",
        )

        errors = manager.validate_profile(profile)
        assert "source_id is required" in errors

    def test_validate_invalid_source_type(self):
        mock_repo = MagicMock()
        manager = SourceOnboardingManager(source_repository=mock_repo)

        profile = SourceProfile(
            source_id="test.source",
            source_name="Test",
            source_type="invalid_type",
            format="syslog",
            parser_id="test",
        )

        errors = manager.validate_profile(profile)
        assert any("Invalid source_type" in e for e in errors)

    def test_validate_invalid_format(self):
        mock_repo = MagicMock()
        manager = SourceOnboardingManager(source_repository=mock_repo)

        profile = SourceProfile(
            source_id="test.source",
            source_name="Test",
            source_type="firewall",
            format="invalid_format",
            parser_id="test",
        )

        errors = manager.validate_profile(profile)
        assert any("Invalid format" in e for e in errors)

    def test_validate_missing_parser_id(self):
        mock_repo = MagicMock()
        manager = SourceOnboardingManager(source_repository=mock_repo)

        profile = SourceProfile(
            source_id="test.source",
            source_name="Test",
            source_type="firewall",
            format="syslog",
            parser_id="",
        )

        errors = manager.validate_profile(profile)
        assert "parser_id is required" in errors

    def test_validate_invalid_source_id_format(self):
        mock_repo = MagicMock()
        manager = SourceOnboardingManager(source_repository=mock_repo)

        profile = SourceProfile(
            source_id="test source with spaces!",
            source_name="Test",
            source_type="firewall",
            format="syslog",
            parser_id="test",
        )

        errors = manager.validate_profile(profile)
        assert any("alphanumeric" in e for e in errors)

    def test_register_new_source(self):
        mock_repo = MagicMock()
        mock_repo.get_by_source_id.return_value = None
        mock_repo.insert.return_value = SourceProfile(
            source_id="firewall.new",
            source_name="New Firewall",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
        )

        manager = SourceOnboardingManager(source_repository=mock_repo)

        profile = SourceProfile(
            source_id="firewall.new",
            source_name="New Firewall",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
        )

        result = manager.register(profile)
        assert result.source_id == "firewall.new"
        mock_repo.insert.assert_called_once()

    def test_register_duplicate_source_updates(self):
        existing = SourceProfile(
            source_id="firewall.dup",
            source_name="Existing",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
            created_at="2026-01-01T00:00:00Z",
        )

        mock_repo = MagicMock()
        mock_repo.get_by_source_id.return_value = existing
        mock_repo.update.return_value = SourceProfile(
            source_id="firewall.dup",
            source_name="Updated",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
        )

        manager = SourceOnboardingManager(source_repository=mock_repo)

        profile = SourceProfile(
            source_id="firewall.dup",
            source_name="Updated",
            source_type="firewall",
            format="syslog",
            parser_id="firewall_syslog_v1",
        )

        result = manager.register(profile)
        assert result.source_name == "Updated"
        mock_repo.update.assert_called_once()

    def test_register_invalid_profile_raises(self):
        mock_repo = MagicMock()
        manager = SourceOnboardingManager(source_repository=mock_repo)

        profile = SourceProfile(
            source_id="",
            source_name="Test",
            source_type="firewall",
            format="syslog",
            parser_id="test",
        )

        try:
            manager.register(profile)
            assert False, "Should have raised ValidationError"
        except ValidationError as ve:
            assert len(ve.errors) > 0

    def test_get_source_caches(self):
        profile = SourceProfile(
            source_id="firewall.cached",
            source_name="Cached",
            source_type="firewall",
            format="syslog",
            parser_id="test",
        )

        mock_repo = MagicMock()
        mock_repo.get_by_source_id.return_value = profile

        manager = SourceOnboardingManager(source_repository=mock_repo)

        result1 = manager.get("firewall.cached")
        result2 = manager.get("firewall.cached")

        assert result1 == result2
        assert result1.source_id == "firewall.cached"
        mock_repo.get_by_source_id.assert_called_once()

    def test_list_sources_filters(self):
        sources = [
            SourceProfile(
                source_id="fw-1",
                source_name="FW1",
                source_type="firewall",
                format="syslog",
                parser_id="test",
                enabled=True,
            ),
            SourceProfile(
                source_id="fw-2",
                source_name="FW2",
                source_type="firewall",
                format="syslog",
                parser_id="test",
                enabled=False,
            ),
            SourceProfile(
                source_id="router-1",
                source_name="R1",
                source_type="router",
                format="json",
                parser_id="test",
                enabled=True,
            ),
        ]

        mock_repo = MagicMock()
        mock_repo.list_all.return_value = sources

        manager = SourceOnboardingManager(source_repository=mock_repo)

        all_sources = manager.list_sources()
        assert len(all_sources) == 3

        firewall_only = manager.list_sources(source_type="firewall")
        assert len(firewall_only) == 2

        enabled_only = manager.list_sources(enabled_only=True)
        assert len(enabled_only) == 2

    def test_enable_source(self):
        profile = SourceProfile(
            source_id="firewall.disabled",
            source_name="Disabled",
            source_type="firewall",
            format="syslog",
            parser_id="test",
            enabled=False,
            status="inactive",
        )

        mock_repo = MagicMock()
        mock_repo.get_by_source_id.return_value = profile
        mock_repo.update.return_value = SourceProfile(
            source_id="firewall.disabled",
            source_name="Disabled",
            source_type="firewall",
            format="syslog",
            parser_id="test",
            enabled=True,
            status="active",
        )

        manager = SourceOnboardingManager(source_repository=mock_repo)
        result = manager.enable("firewall.disabled")

        assert result is not None
        assert result.enabled is True
        assert result.status == "active"

    def test_disable_source(self):
        profile = SourceProfile(
            source_id="firewall.active",
            source_name="Active",
            source_type="firewall",
            format="syslog",
            parser_id="test",
            enabled=True,
            status="active",
        )

        mock_repo = MagicMock()
        mock_repo.get_by_source_id.return_value = profile
        mock_repo.update.return_value = SourceProfile(
            source_id="firewall.active",
            source_name="Active",
            source_type="firewall",
            format="syslog",
            parser_id="test",
            enabled=False,
            status="inactive",
        )

        manager = SourceOnboardingManager(source_repository=mock_repo)
        result = manager.disable("firewall.active")

        assert result is not None
        assert result.enabled is False
        assert result.status == "inactive"

    def test_unregister_source(self):
        mock_repo = MagicMock()
        mock_repo.delete.return_value = True

        manager = SourceOnboardingManager(source_repository=mock_repo)

        result = manager.unregister("firewall.to-delete")
        assert result is True
        mock_repo.delete.assert_called_once_with("firewall.to-delete")

    def test_valid_source_id_patterns(self):
        mock_repo = MagicMock()
        manager = SourceOnboardingManager(source_repository=mock_repo)

        assert manager._is_valid_source_id("firewall.test") is True
        assert manager._is_valid_source_id("router.vendor_x") is True
        assert manager._is_valid_source_id("source.with.dots") is True
        assert manager._is_valid_source_id("source-with-dashes") is True
        assert manager._is_valid_source_id("source_under") is True
        assert manager._is_valid_source_id("Source123") is True

        assert manager._is_valid_source_id("invalid source") is False
        assert manager._is_valid_source_id("invalid!source") is False
        assert manager._is_valid_source_id("") is False
