"""Comprehensive unit and integration test suite for Module 14 Content & Media Intelligence Engine."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from src.container.di import Container
from src.content_intelligence.dom_analyzer import DOMAnalyzer
from src.content_intelligence.engine import ContentIntelligenceEngine
from src.content_intelligence.intent_classifier import IntentClassifier
from src.content_intelligence.media_processor import MediaProcessor
from src.content_intelligence.models import MediaStatus
from src.content_intelligence.module import (
    ContentIntelligenceModule,
    register_content_module,
)
from src.database.models import RawEmail
from src.orchestrator.engine import OrchestratorEngine
from src.parsing.models import ExtractedAttachmentDTO, HeaderAddressDTO, ParsedEmail
from src.registry.module_registry import ModuleRegistry
from src.risk.registry import RiskFeatureRegistry
from src.security_intelligence.ocr.ocr_service import OCRService
from src.security_intelligence.qr.qr_service import QRService


def test_dom_analyzer_signals() -> None:
    """Verify DOMAnalyzer extracts hidden CSS text, form action URLs, script tags, and hex obfuscations."""
    analyzer = DOMAnalyzer()

    html = """
    <html>
        <body>
            <p style="display:none">Urgent password reset required</p>
            <p style="font-size:0px">Hidden text snippet</p>
            <form action="https://phishing-portal.com/login"></form>
            <script>console.log('test')</script>
            <p>&#x50;&#x61;&#x73;&#x73;&#x77;&#x6f;&#x72;&#x64;</p>
        </body>
    </html>
    """

    parsed = ParsedEmail(
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_dom_test",
        internet_message_id="<msg_dom@test.com>",
        sender=HeaderAddressDTO(name="Sender", address="sender@test.com"),
        date=datetime.now(UTC),
        body_html=html,
    )

    signals = analyzer.analyze_dom(parsed)

    assert signals.has_hidden_text is True
    assert len(signals.hidden_text_snippets) >= 2
    assert "https://phishing-portal.com/login" in signals.external_form_actions
    assert signals.script_tag_count == 1
    assert signals.html_entity_obfuscation_count == 8


def test_intent_classifier_signals() -> None:
    """Verify IntentClassifier categorizes primary intent, urgency score, and financial coercion."""
    classifier = IntentClassifier()

    parsed_bec = ParsedEmail(
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_bec_test",
        internet_message_id="<bec@company.com>",
        sender=HeaderAddressDTO(name="CEO", address="ceo@company.com"),
        date=datetime.now(UTC),
        subject="URGENT: Wire Transfer Payment Request",
        body_plain="Please initiate an immediate wire transfer of $10,000 to the attached bank details.",
    )

    res = classifier.classify_email(parsed_bec)

    assert res.primary_intent == "PAYMENT_REQUEST"
    assert res.urgency_detected is True
    assert res.urgency_score > 0.5
    assert res.financial_coercion_detected is True
    assert res.financial_coercion_score > 0.5


def test_media_processor_ocr_qr_statuses() -> None:
    """Verify MediaProcessor extracts text and QR code evidence with honest MediaStatus tracking."""
    processor = MediaProcessor(
        ocr_service=OCRService(force_allow_mock=True),
        qr_service=QRService(force_allow_mock=True),
    )

    parsed = ParsedEmail(
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_media_test",
        internet_message_id="<media@test.com>",
        sender=HeaderAddressDTO(name="Sender", address="sender@test.com"),
        date=datetime.now(UTC),
        attachments=[
            ExtractedAttachmentDTO(
                filename="invoice_receipt.png",
                declared_content_type="image/png",
                detected_mime_type="image/png",
                size_bytes=1024,
                sha256="sha256_mock_1",
                md5="md5_mock_1",
                raw_data=b"png_content_invoice_data",
            ),
            ExtractedAttachmentDTO(
                filename="login_qr.png",
                declared_content_type="image/png",
                detected_mime_type="image/png",
                size_bytes=2048,
                sha256="sha256_mock_2",
                md5="md5_mock_2",
                raw_data=b"QR_http://phishing-portal.com/login",
            ),
        ],
    )

    evidence = processor.process_media(parsed)

    assert evidence.ocr_status == MediaStatus.SUCCESS
    assert "URGENT PAYMENT DUE" in evidence.ocr_extracted_text
    assert evidence.qr_status == MediaStatus.SUCCESS
    assert evidence.qr_detected is True
    assert len(evidence.qr_extracted_urls) > 0


def test_content_feature_extractor_module10_integration() -> None:
    """Verify ContentFeatureExtractor maps content evidence into Module 10 RiskFeatureRegistry."""
    registry = RiskFeatureRegistry()
    extractor = [
        p
        for p in registry._providers.values()
        if p.provider_name == "content_intelligence"
    ][0]

    parsed = ParsedEmail(
        raw_email_id=uuid4(),
        account_id=uuid4(),
        tenant_id=uuid4(),
        message_id="msg_feat_test",
        internet_message_id="<feat@test.com>",
        sender=HeaderAddressDTO(name="User", address="user@company.com"),
        date=datetime.now(UTC),
        body_plain="Urgent action required: Please wire transfer payment invoice immediately.",
        body_html="<p style='display:none'>hidden</p>",
    )

    features = extractor.extract_features(parsed=parsed)

    assert features["has_hidden_text"] is True
    assert features["urgency_score"] > 0.5
    assert features["financial_coercion_score"] > 0.5
    assert features["primary_intent"] == "PAYMENT_REQUEST"


def test_module14_orchestrator_stage35_integration() -> None:
    """Verify Module 12 Pipeline Orchestrator executes Stage 3.5 Content Intelligence cleanly."""

    async def _run() -> None:
        engine = OrchestratorEngine()

        raw_email = RawEmail(
            id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_stage35_test",
            internet_message_id="<stage35@company.com>",
            raw_eml_data=b"From: CEO <ceo@company.com>\r\nTo: rcpt@company.com\r\nSubject: URGENT Wire Transfer\r\n\r\nPlease wire transfer $5000 due now.",
        )

        result = await engine.analyze_email(raw_email)

        assert result.analysis_id is not None
        assert "content_intelligence" in result.sla_metrics
        assert result.risk_assessment is not None
        assert result.decision_plan is not None

    asyncio.run(_run())


def test_content_intelligence_module_lifecycle() -> None:
    """Verify ContentIntelligenceModule DI container registration and health check lifecycle."""

    async def _run() -> None:
        di = Container()
        registry = ModuleRegistry()

        mod = register_content_module(di, registry)
        assert registry.get_module("content_intelligence") == mod

        await registry.initialize_all()

        health = await registry.health_check_all()
        assert health.status == "UP"

        await registry.shutdown_all()

    asyncio.run(_run())
