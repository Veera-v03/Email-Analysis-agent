"""Composition root for Phase 4 URL intelligence.

The engine integrates the previously independent URL analyzers into a single
pipeline that accepts an ``EmailInput`` and returns immutable
``FinalUrlIntelligence`` results for every extracted URL occurrence.
"""

from __future__ import annotations

from src.analyzers.url.anomalies import StructuralUrlAnomalyAnalyzer
from src.analyzers.url.extractor import CompositeUrlExtractor
from src.analyzers.url.features import StructuralUrlFeatureExtractor
from src.analyzers.url.host import DeterministicUrlHostAnalyzer
from src.analyzers.url.hyperlink import DeterministicHyperlinkAnalyzer
from src.analyzers.url.normalizer import CanonicalUrlNormalizer
from src.analyzers.url.reputation import NullReputationProvider
from src.analyzers.url.shortener import DeterministicUrlShortenerDetector
from src.analyzers.url.unicode_analysis import DeterministicUrlUnicodeAnalyzer
from src.models.email import EmailInput
from src.models.url import (
    FinalUrlIntelligence,
    ExtractedUrl,
    HtmlContext,
    HyperlinkObservation,
    NormalizedUrl,
    ParsedUrlComponents,
    RedirectMechanism,
    RedirectResult,
    ReputationResult,
    SuspiciousPatternCategory,
    SuspiciousPatternMatch,
    UrlShortenerAnalysis,
    UrlUnicodeAnalysis,
    UrlEvidence,
    UrlExtractionSource,
)


class UrlIntelligenceEngine:
    """Coordinate Phase 4 URL analyzers through a deterministic pipeline."""

    def __init__(
        self,
        *,
        extractor: CompositeUrlExtractor | None = None,
        normalizer: CanonicalUrlNormalizer | None = None,
        parser: None = None,
        feature_extractor: StructuralUrlFeatureExtractor | None = None,
        host_analyzer: DeterministicUrlHostAnalyzer | None = None,
        unicode_analyzer: DeterministicUrlUnicodeAnalyzer | None = None,
        shortener_detector: DeterministicUrlShortenerDetector | None = None,
        anomaly_analyzer: StructuralUrlAnomalyAnalyzer | None = None,
        hyperlink_analyzer: DeterministicHyperlinkAnalyzer | None = None,
        reputation_provider: NullReputationProvider | None = None,
    ) -> None:
        self._extractor = extractor or CompositeUrlExtractor()
        self._normalizer = normalizer or CanonicalUrlNormalizer()
        self._feature_extractor = feature_extractor or StructuralUrlFeatureExtractor()
        self._host_analyzer = host_analyzer or DeterministicUrlHostAnalyzer()
        self._unicode_analyzer = unicode_analyzer or DeterministicUrlUnicodeAnalyzer()
        self._shortener_detector = (
            shortener_detector or DeterministicUrlShortenerDetector()
        )
        self._anomaly_analyzer = anomaly_analyzer or StructuralUrlAnomalyAnalyzer(
            suspicious_keywords=("login", "verify", "secure", "account")
        )
        self._hyperlink_analyzer = (
            hyperlink_analyzer or DeterministicHyperlinkAnalyzer()
        )
        self._reputation_provider = reputation_provider or NullReputationProvider()

    def analyze(self, email: EmailInput) -> tuple[FinalUrlIntelligence, ...]:
        extracted = self._extractor.extract(email)
        if not extracted:
            return ()

        html_analysis = self._hyperlink_analyzer.analyze(extracted)
        chosen_urls: dict[str, ExtractedUrl] = {}
        for url in extracted:
            key = url.raw_value.lower()
            existing = chosen_urls.get(key)
            if existing is None or (
                url.source is UrlExtractionSource.HTML_ANCHOR
                and existing.source is not UrlExtractionSource.HTML_ANCHOR
            ):
                chosen_urls[key] = url

        results: list[FinalUrlIntelligence] = []
        for url in chosen_urls.values():
            components = self._parse_components(url.raw_value)
            normalized = self._normalizer.normalize(url.raw_value)
            host = self._host_analyzer.analyze(components)
            unicode_analysis = self._unicode_analyzer.analyze(components)
            structural_features = self._feature_extractor.extract(components)
            shortener = self._shortener_detector.detect(components)
            suspicious_patterns = self._anomaly_analyzer.analyze(components)
            if shortener.is_shortened:
                suspicious_patterns = (
                    SuspiciousPatternMatch(
                        category=SuspiciousPatternCategory.KNOWN_SHORTENER,
                        detail="URL host matches a known shortener service",
                    ),
                    *suspicious_patterns,
                )
            html_context = self._html_context(url)
            redirect_result = self._redirect_result(url)
            reputation_result = self._reputation_result(components)
            evidence = self._build_evidence(
                normalized=normalized,
                shortener=shortener,
                suspicious_patterns=suspicious_patterns,
                html_context=html_context,
                redirect_result=redirect_result,
                reputation_result=reputation_result,
                unicode_analysis=unicode_analysis,
                html_observations=html_analysis.observations,
            )
            results.append(
                FinalUrlIntelligence(
                    extracted=url,
                    components=components,
                    normalized=normalized,
                    host=host,
                    unicode_analysis=unicode_analysis,
                    structural_features=structural_features,
                    shortener=shortener,
                    suspicious_patterns=suspicious_patterns,
                    html_context=html_context,
                    redirect_result=redirect_result,
                    reputation_result=reputation_result,
                    evidence=evidence,
                )
            )

        return tuple(results)

    def _parse_components(self, raw_url: str) -> ParsedUrlComponents:
        from urllib.parse import urlsplit

        parsed = urlsplit(raw_url)
        return ParsedUrlComponents(
            scheme=parsed.scheme or None,
            username=parsed.username,
            password=parsed.password,
            host=parsed.hostname,
            port=parsed.port,
            path=parsed.path or None,
            query=parsed.query or None,
            fragment=parsed.fragment or None,
            is_parseable=bool(parsed.scheme or parsed.netloc),
        )

    def _html_context(self, url: ExtractedUrl) -> HtmlContext | None:
        if url.html_context is None:
            if url.source is UrlExtractionSource.HTML_ANCHOR:
                return HtmlContext(tag="a", attribute="href", snippet=None)
            return None
        return HtmlContext(
            tag="a",
            attribute="href",
            snippet=url.html_context,
        )

    def _redirect_result(self, url: ExtractedUrl) -> RedirectResult | None:
        if url.source is UrlExtractionSource.HTML_ANCHOR:
            return RedirectResult(
                mechanism=RedirectMechanism.HTML,
                detected=True,
                target=url.raw_value,
                detail="html anchor href",
            )
        return RedirectResult(
            mechanism=RedirectMechanism.HTTP,
            detected=False,
            detail="no redirect signal",
        )

    def _reputation_result(self, components: ParsedUrlComponents) -> ReputationResult:
        provider = self._reputation_provider.query(components)
        return ReputationResult(
            provider_name=provider.provider_name,
            queried=provider.queried,
            available=provider.available,
            detail="provider stub",
        )

    def _build_evidence(
        self,
        *,
        normalized: NormalizedUrl | None,
        shortener: UrlShortenerAnalysis,
        suspicious_patterns: tuple[SuspiciousPatternMatch, ...],
        html_context: HtmlContext | None,
        redirect_result: RedirectResult | None,
        reputation_result: ReputationResult | None,
        unicode_analysis: UrlUnicodeAnalysis,
        html_observations: tuple[HyperlinkObservation, ...],
    ) -> tuple[UrlEvidence, ...]:
        evidence: list[UrlEvidence] = []
        if normalized is not None and normalized.is_valid:
            evidence.append(
                UrlEvidence(
                    source="normalization", detail="canonicalized", observed=True
                )
            )
        if shortener.is_shortened:
            evidence.append(
                UrlEvidence(
                    source="shortener", detail="matched shortener", observed=True
                )
            )
        if suspicious_patterns:
            evidence.append(
                UrlEvidence(
                    source="anomaly",
                    detail="suspicious pattern detected",
                    observed=True,
                )
            )
        if html_context is not None:
            evidence.append(
                UrlEvidence(
                    source="html", detail="html context captured", observed=True
                )
            )
        if html_observations:
            evidence.append(
                UrlEvidence(
                    source="hyperlink",
                    detail="html hyperlink observations detected",
                    observed=True,
                )
            )
        if redirect_result is not None and redirect_result.detected:
            evidence.append(
                UrlEvidence(
                    source="redirect", detail="redirect signal observed", observed=True
                )
            )
        if reputation_result is not None and reputation_result.queried:
            evidence.append(
                UrlEvidence(
                    source="reputation", detail="provider queried", observed=True
                )
            )
        if unicode_analysis.contains_non_ascii or unicode_analysis.has_mixed_scripts:
            evidence.append(
                UrlEvidence(
                    source="unicode",
                    detail="unicode characteristics observed",
                    observed=True,
                )
            )
        return tuple(evidence)
