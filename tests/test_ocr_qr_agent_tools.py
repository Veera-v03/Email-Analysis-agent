"""Integration coverage for OCR and QR AgentTool adapters."""

from __future__ import annotations

from datetime import UTC, datetime

from src.analyzers.agent.attachments import (
    AttachmentPayload,
    AttachmentTool,
    IAttachmentAnalyzer,
)
from src.analyzers.agent.tools.ocr_tool import OCRTool
from src.analyzers.agent.tools.qr_tool import QRTool
from src.models.agent import AgentState
from src.models.email import EmailAttachment, EmailHeader, EmailInput
from src.planner.orchestration import PlannerOrchestrator
from src.security_intelligence.ocr.ocr_service import OCRService


def _state(
    filename: str = "invoice_qr.png", content_type: str = "image/png"
) -> AgentState:
    email = EmailInput(
        header=EmailHeader(
            message_id="<ocr-qr@example.test>",
            sender="sender@example.test",
            recipients=["recipient@example.test"],
            subject="Invoice",
            sent_at=datetime.now(UTC).isoformat(),
        ),
        body_text="Please review the attachment.",
        attachments=[
            EmailAttachment(filename=filename, content_type=content_type, size_bytes=64)
        ],
    )
    return AgentState.create(
        parsed_email=email,
        metadata={
            "attachment_payloads": [
                AttachmentPayload(
                    filename=filename,
                    content_type=content_type,
                    size_bytes=64,
                    content=b"PNG QR\nhttps://malicious.example/login",
                )
            ]
        },
    )


class _UrlOCRService(OCRService):
    def extract_text(self, filename: str, content: bytes) -> dict[str, object]:
        return {
            "extracted_text": "Visit https://malicious.example/login now",
            "confidence": 0.95,
            "metadata": {"filename": filename},
        }


def test_ocr_tool_generates_canonical_text_and_forwarded_url_evidence() -> None:
    result = OCRTool(ocr_service=_UrlOCRService()).execute(_state())

    assert result.metadata["images_analyzed"] == 1
    assert any(item.category == "ocr_extracted_text" for item in result.evidence)
    assert any(
        item.category.startswith("ocr_forwarded_url_") for item in result.evidence
    )
    assert result.evidence_collection.items


def test_qr_tool_decodes_and_forwards_resolved_url() -> None:
    result = QRTool().execute(_state())

    assert result.metadata["qr_urls_extracted"] == 1
    assert any(item.category == "qr_decoded_content" for item in result.evidence)
    assert any(
        item.category.startswith("qr_forwarded_url_") for item in result.evidence
    )


def test_image_attachment_condition_is_limited_to_images() -> None:
    orchestrator = PlannerOrchestrator.__new__(PlannerOrchestrator)

    assert orchestrator._eval_has_image_attachments(_state())
    assert not orchestrator._eval_has_image_attachments(
        _state("report.pdf", "application/pdf")
    )


class _FailingAnalyzer(IAttachmentAnalyzer):
    def analyze(self, attachment: AttachmentPayload):  # type: ignore[no-untyped-def]
        raise RuntimeError("scanner unavailable")


class _YaraScanner:
    def scan(self, attachment: AttachmentPayload) -> tuple[str, ...]:
        return ("phishing_document",)


def test_attachment_tool_records_analyzer_failure_and_continues() -> None:
    result = AttachmentTool(analyzers=(_FailingAnalyzer(),)).execute(_state())

    diagnostic = next(
        item
        for item in result.evidence
        if item.category == "attachment_analyzer_diagnostic"
    )
    assert diagnostic.metadata["analyzer"] == "_FailingAnalyzer"


def test_attachment_tool_uses_injected_yara_scanner() -> None:
    result = AttachmentTool(yara_scanner=_YaraScanner()).execute(_state())

    assert any(item.category == "attachment_yara" for item in result.evidence)
