"""Dependency-inversion contracts for Phase 4 URL intelligence components.

Every public interface in this module is a ``@runtime_checkable`` Protocol.
Concrete implementations depend on these contracts; consumers depend only on
the protocols. This keeps every analyzer independently testable and replaceable
without modifying the engine or any other component.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from src.models.email import EmailInput
from src.models.url import (
    ExtractedUrl,
    HtmlRedirectSignal,
    HttpRedirectSignal,
    HyperlinkAnalysisResult,
    JavaScriptRedirectSignal,
    NormalizedUrl,
    ParsedUrlComponents,
    RedirectObservation,
    SuspiciousPatternMatch,
    UrlHostAnalysis,
    UrlShortenerAnalysis,
    UrlStructuralFeatures,
    UrlUnicodeAnalysis,
)


@runtime_checkable
class UrlExtractor(Protocol):
    """Extract raw URL occurrences from an email message.

    Implementations must extract from every configured source field and
    preserve the exact raw text and character position of each occurrence.
    No normalization or analysis is performed at this stage.
    """

    def extract(self, email: EmailInput) -> tuple[ExtractedUrl, ...]:
        """Return all URL occurrences found in the supplied email.

        Args:
            email: Validated email input from the Phase 2 boundary.

        Returns:
            Ordered tuple of raw URL occurrences, one per match position.
            Returns an empty tuple when no URLs are found.
        """


@runtime_checkable
class UrlNormalizer(Protocol):
    """Normalize a raw URL string into its canonical form.

    Normalization is purely textual. No DNS resolution, no HTTP requests,
    no redirect following. The result preserves the original raw value
    alongside the canonical form and an audit trail of applied actions.
    """

    def normalize(self, raw_url: str) -> NormalizedUrl:
        """Return the canonical form of a raw URL string.

        Args:
            raw_url: Exact URL text as extracted from the email.

        Returns:
            Normalized URL with audit trail. ``is_valid`` is False when
            the input cannot be safely canonicalized.
        """


@runtime_checkable
class UrlComponentParser(Protocol):
    """Parse a URL string into its RFC 3986 structural components.

    Parsing is structural only. No validation of component values against
    external sources is performed.
    """

    def parse(self, raw_url: str) -> ParsedUrlComponents:
        """Return the structural components of a URL string.

        Args:
            raw_url: Raw or normalized URL text to decompose.

        Returns:
            Parsed components. ``is_parseable`` is False when the input
            cannot be decomposed into any recognizable structure.
        """


@runtime_checkable
class UrlHostAnalyzer(Protocol):
    """Analyze the host component of a parsed URL.

    Host analysis covers type classification (domain, IPv4, IPv6, localhost),
    PSL-based domain decomposition, and IDN/punycode detection. No reputation
    data is consulted.
    """

    def analyze(self, components: ParsedUrlComponents) -> UrlHostAnalysis:
        """Return structural host observations for the supplied URL components.

        Args:
            components: Parsed URL components from a ``UrlComponentParser``.

        Returns:
            Host analysis result. All fields default to safe empty values
            when the host component is absent or unparseable.
        """


@runtime_checkable
class UrlFeatureExtractor(Protocol):
    """Extract deterministic structural features from a parsed URL.

    Features are computed from the URL text alone. No external lookups,
    no heuristics, no scoring.
    """

    def extract(self, components: ParsedUrlComponents) -> UrlStructuralFeatures:
        """Return structural feature measurements for the supplied components.

        Args:
            components: Parsed URL components from a ``UrlComponentParser``.

        Returns:
            Structural feature measurements. All counts are non-negative.
        """


@runtime_checkable
class UrlShortenerDetector(Protocol):
    """Detect whether a URL's host matches a known shortener service.

    Detection is list-based. No HTTP requests are made. The shortener list
    is injected at construction time.
    """

    def detect(self, components: ParsedUrlComponents) -> UrlShortenerAnalysis:
        """Return shortener detection evidence for the supplied components.

        Args:
            components: Parsed URL components from a ``UrlComponentParser``.

        Returns:
            Shortener analysis result. ``is_shortened`` is True only when
            the normalized host exactly matches a configured shortener entry.
        """


@runtime_checkable
class HttpRedirectAnalyzer(Protocol):
    """Analyze an abstract HTTP redirect signal without performing network I/O."""

    def analyze(self, signal: HttpRedirectSignal) -> RedirectObservation:
        """Return a deterministic redirect observation for an HTTP signal."""


@runtime_checkable
class HtmlRedirectAnalyzer(Protocol):
    """Analyze an abstract HTML redirect signal without performing network I/O."""

    def analyze(self, signal: HtmlRedirectSignal) -> RedirectObservation:
        """Return a deterministic redirect observation for an HTML signal."""


@runtime_checkable
class JavaScriptRedirectAnalyzer(Protocol):
    """Analyze an abstract JavaScript redirect signal without performing network I/O."""

    def analyze(self, signal: JavaScriptRedirectSignal) -> RedirectObservation:
        """Return a deterministic redirect observation for a JavaScript signal."""


@runtime_checkable
class UrlPatternAnalyzer(Protocol):
    """Detect deterministic structural patterns in a URL.

    Pattern detection is purely structural. Each match describes an
    observable characteristic without assigning a risk score.
    """

    def analyze(
        self,
        components: ParsedUrlComponents,
        host: UrlHostAnalysis,
        features: UrlStructuralFeatures,
        unicode_analysis: UrlUnicodeAnalysis,
    ) -> tuple[SuspiciousPatternMatch, ...]:
        """Return all structural pattern observations for the supplied URL.

        Args:
            components: Parsed URL components.
            host: Host analysis result.
            features: Structural feature measurements.
            unicode_analysis: Unicode-level observations.

        Returns:
            Ordered tuple of pattern matches. Returns an empty tuple when
            no patterns are observed.
        """


@runtime_checkable
class HyperlinkAnalyzer(Protocol):
    """Analyze HTML hyperlinks extracted from an email message.

    Detects structural characteristics of hyperlinks including anchor text
    mismatches, hidden URLs, scheme-based link types, and presentation
    patterns.  No security verdict is produced.
    """

    def analyze(self, urls: tuple[ExtractedUrl, ...]) -> HyperlinkAnalysisResult:
        """Return all hyperlink observations for the supplied URL occurrences.

        Args:
            urls: Extracted URL occurrences from a ``UrlExtractor``.

        Returns:
            Hyperlink analysis result.  ``observations`` is empty when no
            notable characteristics are detected.
        """


@runtime_checkable
class UrlUnicodeAnalyzer(Protocol):
    """Analyze Unicode characteristics of a URL's components.

    Analysis covers script detection, mixed-script observation, RTL character
    presence, and punycode/percent-encoded Unicode detection. No homoglyph
    resolution is performed.
    """

    def analyze(self, components: ParsedUrlComponents) -> UrlUnicodeAnalysis:
        """Return Unicode-level observations for the supplied URL components.

        Args:
            components: Parsed URL components from a ``UrlComponentParser``.

        Returns:
            Unicode analysis result with script and encoding observations.
        """
