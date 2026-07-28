"""Adapters that expose different header containers through ``HeaderProvider``."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from email.message import Message

HeaderValue = str | Sequence[str] | None


class MappingHeaderProvider:
    """Expose an in-memory header mapping with case-insensitive lookup.

    A sequence value represents repeated occurrences of a header. This is
    useful for test fixtures and parser integrations that retain duplicates.
    """

    def __init__(self, headers: Mapping[str, HeaderValue]) -> None:
        """Create a provider from a header mapping.

        Args:
            headers: Header names mapped to one, many, or no string values.

        Raises:
            TypeError: If a header name or value is not text-based.
        """
        self._headers = self._normalize(headers)

    def get_all(self, header_name: str) -> tuple[str, ...]:
        """Return values for ``header_name`` without regard to name casing."""
        return self._headers.get(header_name.casefold(), ())

    @staticmethod
    def _normalize(headers: Mapping[str, HeaderValue]) -> dict[str, tuple[str, ...]]:
        """Normalize source mapping values while preserving their source order."""
        normalized: dict[str, tuple[str, ...]] = {}
        for header_name, header_value in headers.items():
            if not isinstance(header_name, str):
                message = "Header names must be strings."
                raise TypeError(message)

            values = MappingHeaderProvider._as_values(header_value)
            normalized_name = header_name.casefold()
            normalized[normalized_name] = (
                *normalized.get(normalized_name, ()),
                *values,
            )
        return normalized

    @staticmethod
    def _as_values(header_value: HeaderValue) -> tuple[str, ...]:
        """Return a validated immutable sequence of header values."""
        if header_value is None:
            return ()
        if isinstance(header_value, str):
            return (header_value,)
        if not all(isinstance(value, str) for value in header_value):
            message = "Header values must be strings or sequences of strings."
            raise TypeError(message)
        return tuple(header_value)


class MessageHeaderProvider:
    """Adapt a standard-library ``email.message.Message`` to ``HeaderProvider``."""

    def __init__(self, message: Message) -> None:
        """Create a provider for an already parsed standard-library message."""
        self._message = message

    def get_all(self, header_name: str) -> tuple[str, ...]:
        """Return all header values, preserving their order in the message."""
        values = self._message.get_all(header_name, [])
        return tuple(str(value) for value in values)
