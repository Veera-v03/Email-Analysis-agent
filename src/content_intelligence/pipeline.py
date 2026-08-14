"""Content Intelligence Pipeline orchestrating DOM analysis, NLP intent, and media processing."""

from __future__ import annotations

import time

from src.config.logging import get_logger
from src.content_intelligence.dom_analyzer import DOMAnalyzer
from src.content_intelligence.intent_classifier import IntentClassifier
from src.content_intelligence.media_processor import MediaProcessor
from src.content_intelligence.models import ContentAnalysisResult
from src.parsing.models import ParsedEmail

logger = get_logger("scamon.content_intelligence.pipeline")


class ContentIntelligencePipeline:
    """Orchestrates DOM analysis, intent classification, and media OCR/QR extraction."""

    def __init__(
        self,
        dom_analyzer: DOMAnalyzer | None = None,
        intent_classifier: IntentClassifier | None = None,
        media_processor: MediaProcessor | None = None,
    ) -> None:
        self.dom_analyzer = dom_analyzer or DOMAnalyzer()
        self.intent_classifier = intent_classifier or IntentClassifier()
        self.media_processor = media_processor or MediaProcessor()

    def analyze(self, parsed: ParsedEmail) -> ContentAnalysisResult:
        """Execute complete content intelligence pipeline on ParsedEmail."""
        start_time = time.perf_counter()

        dom_signals = self.dom_analyzer.analyze_dom(parsed)
        intent_analysis = self.intent_classifier.classify_email(parsed)
        media_evidence = self.media_processor.process_media(parsed)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return ContentAnalysisResult(
            parsed_id=parsed.parsed_id,
            tenant_id=parsed.tenant_id,
            message_id=parsed.message_id,
            dom_signals=dom_signals,
            intent_analysis=intent_analysis,
            media_evidence=media_evidence,
            execution_time_ms=elapsed_ms,
        )
