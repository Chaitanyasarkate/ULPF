"""Source Onboarding Manager for ULPF Phase 7.

Provides plug-and-play source registration and management.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ulpf.onboarding.models import LogFormat, SourceProfile, SourceStatus, SourceType

if TYPE_CHECKING:
    from ulpf.parsers.registry import ParserRegistry

logger = logging.getLogger("ulpf.onboarding.manager")


class ValidationError(Exception):
    """Raised when source validation fails."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(f"Validation failed: {'; '.join(errors)}")


class SourceOnboardingManager:
    """Manages source profile registration and discovery.

    Responsibilities:
    - Register new sources with validation
    - Update existing source configurations
    - Enable/disable sources
    - List registered sources
    - Validate source configurations against available parsers
    """

    def __init__(
        self,
        source_repository: Any = None,
        parser_registry: ParserRegistry | None = None,
    ) -> None:
        from ulpf.onboarding.repository import SourceRepository

        self._repository = source_repository or SourceRepository()
        self._parser_registry = parser_registry
        self._source_cache: dict[str, SourceProfile] = {}

    def set_parser_registry(self, registry: ParserRegistry) -> None:
        self._parser_registry = registry

    def validate_profile(self, profile: SourceProfile) -> list[str]:
        errors: list[str] = []

        if not profile.source_id:
            errors.append("source_id is required")
        elif not self._is_valid_source_id(profile.source_id):
            errors.append("source_id must be alphanumeric with dots/underscores/hyphens")

        if not profile.source_name:
            errors.append("source_name is required")

        if not profile.source_type:
            errors.append("source_type is required")
        elif profile.source_type not in SourceType.values():
            errors.append(
                f"Invalid source_type: {profile.source_type}. "
                f"Valid types: {', '.join(SourceType.values())}"
            )

        if not profile.format:
            errors.append("format is required")
        elif profile.format not in LogFormat.values():
            errors.append(
                f"Invalid format: {profile.format}. "
                f"Valid formats: {', '.join(LogFormat.values())}"
            )

        if not profile.parser_id:
            errors.append("parser_id is required")

        if self._parser_registry and profile.parser_id:
            parser = self._get_parser_by_id(profile.parser_id)
            if parser is None:
                errors.append(f"Parser not found: {profile.parser_id}")
            elif profile.parser_version and profile.parser_version != parser.parser_version:
                logger.warning(
                    "Parser version mismatch for %s: expected %s, got %s",
                    profile.parser_id,
                    parser.parser_version,
                    profile.parser_version,
                )

        if profile.normalizer_id:
            normalizer = self._get_normalizer_by_id(profile.normalizer_id)
            if normalizer is None:
                logger.warning("Normalizer not found: %s", profile.normalizer_id)

        return errors

    def register(self, profile: SourceProfile) -> SourceProfile:
        errors = self.validate_profile(profile)
        if errors:
            raise ValidationError(errors)

        existing = self._repository.get_by_source_id(profile.source_id)
        if existing:
            profile.created_at = existing.created_at
            profile.update()
            result = self._repository.update(profile)
        else:
            result = self._repository.insert(profile)

        self._source_cache[profile.source_id] = result
        logger.info("Registered source: %s", profile.source_id)
        return result

    def unregister(self, source_id: str) -> bool:
        if source_id in self._source_cache:
            del self._source_cache[source_id]
        return self._repository.delete(source_id)

    def enable(self, source_id: str) -> SourceProfile | None:
        profile = self._repository.get_by_source_id(source_id)
        if not profile:
            return None

        profile.enabled = True
        profile.status = SourceStatus.ACTIVE.value
        profile.update()

        result = self._repository.update(profile)
        if result:
            self._source_cache[source_id] = result
        return result

    def disable(self, source_id: str) -> SourceProfile | None:
        profile = self._repository.get_by_source_id(source_id)
        if not profile:
            return None

        profile.enabled = False
        profile.status = SourceStatus.INACTIVE.value
        profile.update()

        result = self._repository.update(profile)
        if result:
            self._source_cache[source_id] = result
        return result

    def get(self, source_id: str) -> SourceProfile | None:
        if source_id in self._source_cache:
            return self._source_cache[source_id]

        profile = self._repository.get_by_source_id(source_id)
        if profile:
            self._source_cache[source_id] = profile
        return profile

    def list_sources(
        self,
        source_type: str | None = None,
        enabled_only: bool = False,
    ) -> list[SourceProfile]:
        sources = self._repository.list_all()
        filtered = []

        for source in sources:
            if source_type and source.source_type != source_type:
                continue
            if enabled_only and not source.enabled:
                continue
            filtered.append(source)

        return filtered

    def get_by_parser(self, parser_id: str) -> list[SourceProfile]:
        return self._repository.get_by_parser_id(parser_id)

    def _get_parser_by_id(self, parser_id: str) -> Any:
        if not self._parser_registry:
            return None
        for parser in self._parser_registry.all_parsers():
            if parser.parser_id == parser_id:
                return parser
        return None

    def _get_normalizer_by_id(self, normalizer_id: str) -> Any:
        return None

    @staticmethod
    def _is_valid_source_id(source_id: str) -> bool:
        import re
        return bool(re.match(r"^[a-zA-Z0-9._-]+$", source_id))
