"""Intent Classifier analyzing linguistic intent, urgency, and coercion using BehaviorAnalyzer."""

from __future__ import annotations

from src.content_intelligence.models import ContentIntentAnalysisDTO
from src.parsing.models import ParsedEmail
from src.security_intelligence.behavior.behavior_analyzer import BehaviorAnalyzer


class IntentClassifier:
    """Categorizes text content into primary intent, urgency score, and financial coercion indicators."""

    def __init__(self, behavior_analyzer: BehaviorAnalyzer | None = None) -> None:
        self.behavior_analyzer = behavior_analyzer or BehaviorAnalyzer()

    def classify_email(self, parsed: ParsedEmail) -> ContentIntentAnalysisDTO:
        """Classify combined email subject, body_plain, and body_html text."""
        combined_text = f"{parsed.subject}\n{parsed.body_plain}"
        res = self.behavior_analyzer.classify_intent(combined_text)

        return ContentIntentAnalysisDTO(
            primary_intent=res["primary_intent"],
            urgency_detected=res["urgency_detected"],
            urgency_score=res["urgency_score"],
            financial_coercion_detected=res["financial_coercion_detected"],
            financial_coercion_score=res["financial_coercion_score"],
            detected_tactics=res["detected_tactics"],
        )
