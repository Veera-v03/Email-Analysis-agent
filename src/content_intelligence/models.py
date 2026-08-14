"""Content Intelligence output models and DTO schemas matching Module 14 Specification."""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import Field

from src.common.models import BaseDTO


class MediaStatus(StrEnum):
    """Honest status tracking for media extraction engines."""

    SUCCESS = "SUCCESS"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class DOMContentSignalsDTO(BaseDTO):
    """HTML DOM structural anomaly signals extracted by DOMAnalyzer."""

    has_hidden_text: bool = Field(
        default=False, description="Flag indicating CSS hidden text or zero-font text"
    )
    hidden_text_snippets: list[str] = Field(
        default_factory=list, description="Extracted hidden text snippets"
    )
    external_form_actions: list[str] = Field(
        default_factory=list, description="Extracted <form action='...'> target URLs"
    )
    script_tag_count: int = Field(default=0, description="Count of <script> elements")
    html_entity_obfuscation_count: int = Field(
        default=0, description="Count of &#x... hex obfuscations"
    )


class ContentIntentAnalysisDTO(BaseDTO):
    """Linguistic intent, urgency, and financial coercion signals extracted by IntentClassifier."""

    primary_intent: str = Field(
        default="LEGITIMATE",
        description="PAYMENT_REQUEST, CREDENTIAL_UPDATE, URGENT_VERIFICATION, SPAM, LEGITIMATE",
    )
    urgency_detected: bool = Field(
        default=False, description="Urgency manipulation detected"
    )
    urgency_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Urgency score (0.0 to 1.0)"
    )
    financial_coercion_detected: bool = Field(
        default=False, description="Financial pressure/BEC detected"
    )
    financial_coercion_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Financial coercion score (0.0 to 1.0)"
    )
    detected_tactics: list[str] = Field(
        default_factory=list, description="List of detected social engineering tactics"
    )


class ContentMediaEvidenceDTO(BaseDTO):
    """Honest OCR and QR code media extraction evidence extracted by MediaProcessor."""

    ocr_status: MediaStatus = Field(
        default=MediaStatus.SKIPPED, description="OCR engine status"
    )
    ocr_extracted_text: str = Field(
        default="", description="Extracted text from image or PDF attachment"
    )
    ocr_confidence: float = Field(
        default=0.0, ge=0.0, le=1.0, description="OCR extraction confidence"
    )
    qr_status: MediaStatus = Field(
        default=MediaStatus.SKIPPED, description="QR decoder engine status"
    )
    qr_detected: bool = Field(
        default=False, description="Flag indicating QR code matrix detected"
    )
    qr_extracted_urls: list[str] = Field(
        default_factory=list, description="Extracted URLs embedded in QR codes"
    )


class ContentAnalysisResult(BaseDTO):
    """Universal immutable output object representing complete content and media intelligence."""

    analysis_id: UUID = Field(
        default_factory=uuid4, description="Unique content analysis UUID"
    )
    parsed_id: UUID = Field(description="Parent ParsedEmail UUID reference")
    tenant_id: UUID = Field(description="Associated Tenant UUID")
    message_id: str = Field(description="Provider message ID")
    dom_signals: DOMContentSignalsDTO = Field(description="DOM structural signals")
    intent_analysis: ContentIntentAnalysisDTO = Field(
        description="NLP intent, urgency, and coercion signals"
    )
    media_evidence: ContentMediaEvidenceDTO = Field(
        description="OCR and QR media evidence"
    )
    execution_time_ms: float = Field(
        default=0.0, description="Content intelligence execution duration in ms"
    )
