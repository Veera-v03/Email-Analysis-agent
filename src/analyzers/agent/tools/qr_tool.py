"""AgentTool adapter for the existing QR intelligence service."""

from __future__ import annotations

import time
from urllib.parse import urlparse

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
from src.security_intelligence.qr.qr_service import QRService


class QRTool(AgentTool[AgentState]):
    """Decode QR content from image attachments and reuse URL intelligence."""

    def __init__(
        self,
        metadata: ToolMetadata | None = None,
        qr_service: QRService | None = None,
        url_tool: URLTool | None = None,
    ) -> None:
        super().__init__(
            metadata
            or ToolMetadata(
                name="qr_tool",
                description=(
                    "Decodes QR codes in image attachments and analyzes embedded links."
                ),
                version="1.0.0",
                capabilities=(ToolCapability.CONTENT, ToolCapability.ATTACHMENT),
                tags=("qr", "image", "link_security"),
            )
        )
        self._qr_service = qr_service or QRService()
        self._url_tool = url_tool or URLTool()
        self._attachment_tool = AttachmentTool()

    def execute(self, input_data: AgentState) -> ToolResult:
        started_ns = time.perf_counter_ns()
        evidence: list[ToolEvidence] = []
        urls: list[str] = []
        payloads = self._attachment_tool._extract_payloads(input_data)
        image_payloads = [item for item in payloads if self._is_image(item)]
        for payload in image_payloads:
            result = self._qr_service.extract_and_decode(
                payload.filename, payload.content
            )
            if not result.get("qr_detected", False):
                continue
            raw = result.get("raw_url")
            resolved = result.get("resolved_url")
            qr_type = urlparse(str(raw or "")).scheme or "unknown"
            evidence.append(
                ToolEvidence(
                    category="qr_decoded_content",
                    detail=(
                        f"Decoded QR content from '{payload.filename}': "
                        f"{raw or resolved}"
                    ),
                    metadata={
                        "severity": "high" if result.get("is_malicious") else "info",
                        "filename": payload.filename,
                        "raw_content": raw,
                        "resolved_content": resolved,
                        "qr_type": qr_type,
                        **dict(result.get("metadata", {})),
                    },
                )
            )
            if isinstance(resolved, str) and resolved.startswith(
                ("http://", "https://")
            ):
                urls.append(resolved)
        evidence.extend(self._forward_urls(input_data, tuple(dict.fromkeys(urls))))
        elapsed_ms = max(0, int((time.perf_counter_ns() - started_ns) / 1_000_000))
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            metadata={
                "images_analyzed": len(image_payloads),
                "qr_urls_extracted": len(set(urls)),
            },
            evidence=tuple(evidence),
            execution_time_ms=elapsed_ms,
        )

    @staticmethod
    def _is_image(payload: AttachmentPayload) -> bool:
        return payload.filename.lower().endswith(
            (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp")
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
                category=f"qr_forwarded_{item.category}",
                detail=item.detail,
                metadata={**item.metadata, "forwarded_by": self.metadata.name},
            )
            for item in result.evidence
        )
