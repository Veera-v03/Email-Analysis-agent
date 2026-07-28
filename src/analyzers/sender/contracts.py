"""Dependency-inversion contracts for sender extraction."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from src.models.sender import ParsedEmailAddress, SenderAnalysisResult


@runtime_checkable
class HeaderProvider(Protocol):
    """Provide all values for a message header without exposing MIME internals."""

    def get_all(self, header_name: str) -> tuple[str, ...]:
        """Return every value of ``header_name`` in source order."""


@runtime_checkable
class AddressParser(Protocol):
    """Parse RFC address header values into structured address evidence."""

    def parse(self, header_values: tuple[str, ...]) -> tuple[ParsedEmailAddress, ...]:
        """Extract zero or more address values from supplied header values."""


@runtime_checkable
class SenderExtractor(Protocol):
    """Extract sender and recipient evidence from an abstract header source."""

    def extract(self, headers: HeaderProvider) -> SenderAnalysisResult:
        """Build a sender-intelligence result without making a risk judgement."""
