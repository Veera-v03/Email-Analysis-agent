"""Regression tests for Milestone 4.6 URL shortener detection."""

from __future__ import annotations

from src.analyzers.url import DeterministicUrlShortenerDetector
from src.analyzers.url.contracts import UrlShortenerDetector
from src.analyzers.url.shortener import ShortenerRegistry, ShortenerServiceDefinition
from src.models.url import ParsedUrlComponents


def _components(host: str) -> ParsedUrlComponents:
    return ParsedUrlComponents(scheme="https", host=host, path="/", is_parseable=True)


def test_detector_matches_known_shortener_hosts() -> None:
    """Known shortener hosts should be detected deterministically."""
    detector = DeterministicUrlShortenerDetector()

    result = detector.detect(_components("bit.ly"))

    assert result.is_shortened is True
    assert result.matched_shortener_host == "bit.ly"


def test_detector_matches_registered_aliases() -> None:
    """Registry aliases should resolve to the canonical service entry."""
    registry = ShortenerRegistry(
        [
            ShortenerServiceDefinition(
                host="example-shortener.com", aliases=("go.example",)
            )
        ]
    )
    detector = DeterministicUrlShortenerDetector(registry)

    result = detector.detect(_components("go.example"))

    assert result.is_shortened is True
    assert result.matched_shortener_host == "example-shortener.com"


def test_detector_uses_www_normalization_for_match() -> None:
    """A leading www subdomain should not block detection."""
    detector = DeterministicUrlShortenerDetector()

    result = detector.detect(_components("www.tinyurl.com"))

    assert result.is_shortened is True
    assert result.matched_shortener_host == "tinyurl.com"


def test_detector_satisfies_url_shortener_detector_protocol() -> None:
    """The implementation should conform to the URL shortener detector protocol."""
    assert isinstance(DeterministicUrlShortenerDetector(), UrlShortenerDetector)
