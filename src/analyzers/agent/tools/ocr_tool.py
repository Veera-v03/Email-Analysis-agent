"""AgentTool adapter for the existing OCR intelligence service."""

from __future__ import annotations

import re
import time

from src.analyzers.agent.attachments.models import AttachmentPayload
from src.analyzers.agent.attachments.tool import AttachmentTool
from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.tools.url_tool import URLTool
from src.models.agent import (
    AgentState,
    ToolCapability,
    ToolEvidence,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)
from src.security_intelligence.ocr.ocr_service import OCRService

_URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_EMAIL_PATTERN = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
_PHONE_PATTERN = re.compile(r"\+?\d[\d(). -]{6,}\d")
_IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".webp")


class OCRTool(AgentTool[AgentState]):
    """Extract OCR intelligence from image attachments and forward discovered URLs."""

    def __init__(
        self,
        metadata: ToolMetadata | None = None,
        ocr_service: OCRService | None = None,
        url_tool: URLTool | None = None,
    ) -> None:
        super().__init__(
            metadata
            or ToolMetadata(
                name="ocr_tool",
                description=(
                    "Extracts security-relevant text and entities from "
                    "image attachments."
                ),
                version="1.0.0",
                capabilities=(ToolCapability.CONTENT, ToolCapability.ATTACHMENT),
                tags=("ocr", "image", "content_security"),
            )
        )
        self._ocr_service = ocr_service or OCRService()
        self._url_tool = url_tool or URLTool()
        self._attachment_tool = AttachmentTool()

    def execute(self, input_data: AgentState) -> ToolResult:
        started_ns = time.perf_counter_ns()
        evidence: list[ToolEvidence] = []
        urls: list[str] = []
        payloads = self._attachment_tool._extract_payloads(input_data)
        image_payloads = [item for item in payloads if self._is_image(item)]
        for payload in image_payloads:
            result = self._ocr_service.extract_text(payload.filename, payload.content)
            text = str(result.get("extracted_text", ""))
            confidence = result.get("confidence", 0.0)
            extracted_urls = _URL_PATTERN.findall(text)
            urls.extend(extracted_urls)
            evidence.append(
                ToolEvidence(
                    category="ocr_extracted_text",
                    detail=f"OCR extracted text from '{payload.filename}': {text}",
                    metadata={
                        "severity": "info",
                        "confidence": confidence,
                        "filename": payload.filename,
                        **dict(result.get("metadata", {})),
                    },
                )
            )
            for category, values in (
                ("ocr_url", extracted_urls),
                ("ocr_email_address", _EMAIL_PATTERN.findall(text)),
                ("ocr_phone_number", _PHONE_PATTERN.findall(text)),
            ):
                for value in values:
                    evidence.append(
                        ToolEvidence(
                            category=category,
                            detail=(
                                "OCR detected "
                                f"{category.removeprefix('ocr_').replace('_', ' ')} "
                                f"'{value}' in '{payload.filename}'."
                            ),
                            metadata={
                                "severity": "medium"
                                if category == "ocr_url"
                                else "info",
                                "confidence": confidence,
                                "filename": payload.filename,
                                "value": value,
                            },
                        )
                    )
        evidence.extend(self._forward_urls(input_data, tuple(dict.fromkeys(urls))))
        elapsed_ms = max(0, int((time.perf_counter_ns() - started_ns) / 1_000_000))
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            metadata={
                "images_analyzed": len(image_payloads),
                "urls_extracted": len(set(urls)),
            },
            evidence=tuple(evidence),
            execution_time_ms=elapsed_ms,
        )

    @staticmethod
    def _is_image(payload: AttachmentPayload) -> bool:
        return payload.filename.lower().endswith(
            _IMAGE_EXTENSIONS
        ) or payload.content_type.lower().startswith("image/")

    def _forward_urls(
        self, state: AgentState, urls: tuple[str, ...]
    ) -> tuple[ToolEvidence, ...]:
        if not urls or state.parsed_email is None:
            return ()
        forwarded_email = state.parsed_email.model_copy(
            update={"body_text": "\n".join(urls)}
        )
        result = self._url_tool.execute(
            state.model_copy(update={"parsed_email": forwarded_email})
        )
        return tuple(
            ToolEvidence(
                category=f"ocr_forwarded_{item.category}",
                detail=item.detail,
                metadata={**item.metadata, "forwarded_by": self.metadata.name},
            )
            for item in result.evidence
        )
