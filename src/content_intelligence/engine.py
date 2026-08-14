"""Central ContentIntelligenceEngine executing pipeline and emitting telemetry."""

from __future__ import annotations

from src.config.logging import get_logger
from src.content_intelligence.models import ContentAnalysisResult
from src.content_intelligence.pipeline import ContentIntelligencePipeline
from src.parsing.models import ParsedEmail

logger = get_logger("scamon.content_intelligence.engine")


class ContentIntelligenceEngine:
    """Central engine executing content intelligence pipeline for ParsedEmail."""

    def __init__(self, pipeline: ContentIntelligencePipeline | None = None) -> None:
        self.pipeline = pipeline or ContentIntelligencePipeline()

    async def analyze_content(self, parsed: ParsedEmail) -> ContentAnalysisResult:
        """Analyze content, DOM structural signals, intent, OCR, and QR codes."""
        result = self.pipeline.analyze(parsed)

        logger.info(
            "Content intelligence completed for msg '%s': intent=%s, hidden_text=%s, OCR_status=%s, QR_detected=%s in %.2fms",
            result.message_id,
            result.intent_analysis.primary_intent,
            result.dom_signals.has_hidden_text,
            result.media_evidence.ocr_status.value,
            result.media_evidence.qr_detected,
            result.execution_time_ms,
        )
        return result
