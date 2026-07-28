"""Reputation provider abstractions for future URL intelligence integrations.

This milestone introduces interfaces only. No API keys, no network requests,
and no provider-specific execution logic are included. The abstractions are
intended to support future providers such as VirusTotal, Google Safe Browsing,
URLhaus, and AbuseIPDB.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from src.models.url import ParsedUrlComponents


@runtime_checkable
class UrlReputationProvider(Protocol):
    """Describe a provider abstraction for reputation-style lookups."""

    name: str

    def query(self, components: ParsedUrlComponents) -> "UrlReputationResult":
        """Return a deterministic provider result for the supplied components."""


class UrlReputationResult(ABC):
    """Base contract for provider outcomes without performing any I/O."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider identifier for this result."""

    @property
    @abstractmethod
    def queried(self) -> bool:
        """Return whether a query was attempted."""

    @property
    @abstractmethod
    def available(self) -> bool:
        """Return whether the provider is available for future use."""


class NullReputationProvider:
    """A placeholder provider used to preserve the interface contract."""

    name = "null"

    def query(self, components: ParsedUrlComponents) -> UrlReputationResult:
        return NullReputationResult()


class NullReputationResult(UrlReputationResult):
    """A no-op result that satisfies the provider contract without I/O."""

    @property
    def provider_name(self) -> str:
        return "null"

    @property
    def queried(self) -> bool:
        return False

    @property
    def available(self) -> bool:
        return False
