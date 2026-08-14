"""Central URLIntelligenceEngine executing pipeline and emitting telemetry."""

from __future__ import annotations

from src.config.logging import get_logger
from src.content_intelligence.models import ContentAnalysisResult
from src.parsing.models import ParsedEmail
from src.url_intelligence.models import URLAnalysisResult
from src.url_intelligence.pipeline import URLIntelligencePipeline

logger = get_logger("scamon.url_intelligence.engine")


class URLIntelligenceEngine:
    """Central engine executing URL & Sandbox Intelligence Pipeline for ParsedEmail."""

    def __init__(self, pipeline: URLIntelligencePipeline | None = None) -> None:
        self.pipeline = pipeline or URLIntelligencePipeline()

    async def analyze_urls(
        self,
        parsed: ParsedEmail,
        content_res: ContentAnalysisResult | None = None,
    ) -> URLAnalysisResult:
        """Analyze email URLs, perform SSRF checks, redirect expansion, and browser sandboxing."""
        result = self.pipeline.analyze_urls(parsed, content_res=content_res)

        logger.info(
            "URL intelligence completed for msg '%s': count=%d, mismatched=%s, SSRF_violation=%s, hops=%d, sandbox_status=%s in %.2fms",
            result.message_id,
            result.extracted_urls_count,
            result.has_mismatched_urls,
            result.ssrf_violation_detected,
            result.redirect_chain.total_hops,
            result.sandbox_result.sandbox_status.value,
            result.execution_time_ms,
        )
        return result
