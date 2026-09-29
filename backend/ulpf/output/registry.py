"""Output formatter registry for ULPF Phase 9A."""

from __future__ import annotations

import logging

from ulpf.output.base import BaseFormatter, OutputFormat

logger = logging.getLogger("ulpf.output.registry")


class UnknownFormatError(ValueError):
    """Raised when an unknown output format is requested."""


class OutputFormatterRegistry:
    """Registry of available output formatters.

    Formatters can be registered programmatically. The registry supports
    lookup by output format, returning the matching formatter.
    """

    _instance: OutputFormatterRegistry | None = None

    def __init__(self) -> None:
        self._formatters: dict[OutputFormat, BaseFormatter] = {}

    @classmethod
    def get_instance(cls) -> OutputFormatterRegistry:
        """Get singleton registry instance."""
        if cls._instance is None:
            cls._instance = cls()
            cls._instance._register_default_formatters()
        return cls._instance

    def register(self, formatter: BaseFormatter) -> None:
        """Register a formatter instance.

        Args:
            formatter: A ``BaseFormatter`` subclass instance.
        """
        self._formatters[formatter.output_format] = formatter
        logger.debug(
            "Registered formatter formatter_id=%s output_format=%s",
            formatter.formatter_id,
            formatter.output_format.value,
        )

    def get_formatter(self, fmt: OutputFormat | str) -> BaseFormatter:
        """Get formatter for the given output format.

        Args:
            fmt: Output format (enum or string).

        Returns:
            The matching formatter.

        Raises:
            UnknownFormatError: If no formatter is registered for the format.
        """
        if isinstance(fmt, str):
            try:
                fmt = OutputFormat.from_string(fmt)
            except ValueError as exc:
                raise UnknownFormatError(str(exc)) from exc

        if fmt not in self._formatters:
            valid = ", ".join(f.value for f in self._formatters)
            raise UnknownFormatError(
                f"No formatter registered for format '{fmt.value}'. Available formats: {valid}"
            )
        return self._formatters[fmt]

    def all_formatters(self) -> list[BaseFormatter]:
        """Return all registered formatters."""
        return list(self._formatters.values())

    def list_formats(self) -> list[str]:
        """Return list of registered format names."""
        return [fmt.value for fmt in self._formatters]

    def _register_default_formatters(self) -> None:
        """Register all built-in formatters."""
        from ulpf.output.cef_formatter import CEFFormatter
        from ulpf.output.csv_formatter import CSVFormatter
        from ulpf.output.json_formatter import JSONFormatter
        from ulpf.output.leef_formatter import LEEFFormatter
        from ulpf.output.ocsf_formatter import OCSFFormatter
        from ulpf.output.syslog_formatter import SyslogFormatter
        from ulpf.output.xml_formatter import XMLFormatter

        self.register(JSONFormatter())
        self.register(CEFFormatter())
        self.register(LEEFFormatter())
        self.register(XMLFormatter())
        self.register(CSVFormatter())
        self.register(SyslogFormatter())
        self.register(OCSFFormatter())
        logger.info("Registered %d output formatters", len(self._formatters))


def get_formatter(fmt: OutputFormat | str) -> BaseFormatter:
    """Convenience function to get a formatter from the registry."""
    return OutputFormatterRegistry.get_instance().get_formatter(fmt)
