"""Phase 4 URL intelligence analysis components.

This package coordinates URL extraction, normalization, structural analysis,
and pattern detection for email messages. No component in this package
performs live network requests, reputation lookups, or security verdicts.
"""

from src.analyzers.url.anomalies import StructuralUrlAnomalyAnalyzer
from src.analyzers.url.contracts import (
    HyperlinkAnalyzer,
    UrlExtractor,
    UrlFeatureExtractor,
    UrlHostAnalyzer,
    UrlNormalizer,
    UrlPatternAnalyzer,
    UrlShortenerDetector,
    UrlUnicodeAnalyzer,
)
from src.analyzers.url.engine import UrlIntelligenceEngine
from src.analyzers.url.extractor import (
    CompositeUrlExtractor,
    HtmlUrlExtractor,
    RegexUrlExtractor,
)
from src.analyzers.url.features import StructuralUrlFeatureExtractor
from src.analyzers.url.hyperlink import (
    DeterministicHyperlinkAnalyzer,
    detect_anchor_text_mismatch,
)
from src.analyzers.url.normalizer import CanonicalUrlNormalizer
from src.analyzers.url.reputation import (
    NullReputationProvider,
    NullReputationResult,
    UrlReputationProvider,
)
from src.analyzers.url.shortener import DeterministicUrlShortenerDetector
from src.analyzers.url.unicode_analysis import DeterministicUrlUnicodeAnalyzer

__all__ = [
    "CanonicalUrlNormalizer",
    "CompositeUrlExtractor",
    "DeterministicHyperlinkAnalyzer",
    "DeterministicUrlShortenerDetector",
    "DeterministicUrlUnicodeAnalyzer",
    "HtmlUrlExtractor",
    "HyperlinkAnalyzer",
    "RegexUrlExtractor",
    "NullReputationProvider",
    "NullReputationResult",
    "StructuralUrlAnomalyAnalyzer",
    "StructuralUrlFeatureExtractor",
    "UrlExtractor",
    "UrlIntelligenceEngine",
    "UrlFeatureExtractor",
    "UrlHostAnalyzer",
    "UrlNormalizer",
    "UrlPatternAnalyzer",
    "UrlShortenerDetector",
    "UrlUnicodeAnalyzer",
    "detect_anchor_text_mismatch",
]
