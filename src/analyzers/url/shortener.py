"""Deterministic shortener detection for Phase 4 URL intelligence.

The implementation is intentionally narrow: it matches a URL host against a
registry of known shortening services and returns a structured result for the
URL intelligence pipeline. The registry is designed to be expanded later for
redirect-aware heuristics without changing the public analyzer contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from src.models.url import ParsedUrlComponents, UrlShortenerAnalysis


@dataclass(frozen=True, slots=True)
class ShortenerServiceDefinition:
    """Describe one known shortener service and its supported aliases."""

    host: str
    aliases: tuple[str, ...] = field(default_factory=tuple)


class ShortenerRegistry:
    """Provide deterministic host matching for known shortening services.

    The registry stores a canonical host plus optional aliases. Matching is
    case-insensitive and normalizes a leading ``www.`` label so services can
    be detected even when the URL uses the common ``www`` prefix.
    """

    def __init__(
        self, services: Iterable[ShortenerServiceDefinition] | None = None
    ) -> None:
        self._services: tuple[ShortenerServiceDefinition, ...] = tuple(services or ())

    def match(self, host: str | None) -> str | None:
        """Return the canonical shortener host when the supplied host matches.

        Args:
            host: The host value from parsed URL components.

        Returns:
            The canonical host for a matched shortener service, otherwise ``None``.
        """
        if not host:
            return None

        normalized = self._normalize_host(host)
        if not normalized:
            return None

        for service in self._services:
            if normalized == self._normalize_host(service.host):
                return service.host
            for alias in service.aliases:
                if normalized == self._normalize_host(alias):
                    return service.host
        return None

    @staticmethod
    def _normalize_host(host: str) -> str:
        """Normalize host values for deterministic comparison."""
        value = host.strip().lower()
        if value.startswith("www."):
            value = value[4:]
        return value


class DeterministicUrlShortenerDetector:
    """Detect known URL-shortening services from parsed URL components.

    The detector is intentionally stateless and deterministic. It does not make
    network requests or follow redirects. It only inspects the host component
    against a configurable registry.
    """

    def __init__(self, registry: ShortenerRegistry | None = None) -> None:
        self._registry = registry or self._default_registry()

    def detect(self, components: ParsedUrlComponents) -> UrlShortenerAnalysis:
        """Return shortener evidence for the supplied URL components.

        Args:
            components: Parsed components extracted from a URL.

        Returns:
            A ``UrlShortenerAnalysis`` with ``is_shortened`` set when the host
            matches a known shortener service.
        """
        host = components.host
        matched = self._registry.match(host)
        return UrlShortenerAnalysis(
            is_shortened=matched is not None,
            matched_shortener_host=matched,
        )

    @staticmethod
    def _default_registry() -> ShortenerRegistry:
        """Create the default registry of known shortening services."""
        services = (
            ShortenerServiceDefinition(host="bit.ly", aliases=("bitly.com",)),
            ShortenerServiceDefinition(host="tinyurl.com", aliases=("tinyurl.com",)),
            ShortenerServiceDefinition(host="t.co", aliases=("twitter.com", "x.com")),
            ShortenerServiceDefinition(host="ow.ly", aliases=()),
            ShortenerServiceDefinition(host="goo.gl", aliases=()),
            ShortenerServiceDefinition(host="is.gd", aliases=()),
            ShortenerServiceDefinition(host="tiny.cc", aliases=()),
        )
        return ShortenerRegistry(services)
