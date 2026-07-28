"""Metadata analyzer for basic attachment validation."""

from __future__ import annotations

from src.analyzers.agent.attachments.base import IAttachmentAnalyzer
from src.analyzers.agent.attachments.models import AttachmentPayload
from src.models.agent import ToolEvidence

UNSUPPORTED_MIME_PREFIXES = (
    "application/x-ms-",
    "application/x-dosexec",
    "application/x-executable",
)


class AttachmentMetadataAnalyzer(IAttachmentAnalyzer):
    """Analyze basic attachment metadata including filename, MIME type, and size."""

    def analyze(self, attachment: AttachmentPayload) -> list[ToolEvidence]:
        """Analyze attachment metadata and return evidence."""
        evidence: list[ToolEvidence] = []

        # 1. Missing filename
        filename = attachment.filename.strip()
        if not filename:
            evidence.append(
                ToolEvidence(
                    category="attachment_metadata",
                    detail="Attachment lacks a valid filename.",
                    metadata={
                        "severity": "medium",
                        "confidence": 0.9,
                        "field": "filename",
                    },
                )
            )

        # 2. Missing content-type
        content_type = attachment.content_type.strip().lower()
        if not content_type:
            evidence.append(
                ToolEvidence(
                    category="attachment_metadata",
                    detail=f"Attachment '{filename or 'unnamed'}' lacks a declared MIME type.",
                    metadata={
                        "severity": "medium",
                        "confidence": 0.9,
                        "field": "content_type",
                    },
                )
            )
        elif content_type == "application/octet-stream":
            evidence.append(
                ToolEvidence(
                    category="attachment_metadata",
                    detail=(
                        f"Attachment '{filename or 'unnamed'}' uses generic binary MIME type "
                        "'application/octet-stream'."
                    ),
                    metadata={
                        "severity": "low",
                        "confidence": 0.7,
                        "content_type": content_type,
                    },
                )
            )

        # 3. Size validation
        actual_size = len(attachment.content) if attachment.content else attachment.size_bytes
        if actual_size == 0:
            evidence.append(
                ToolEvidence(
                    category="attachment_metadata",
                    detail=f"Attachment '{filename or 'unnamed'}' has size 0 bytes.",
                    metadata={
                        "severity": "low",
                        "confidence": 0.95,
                        "size_bytes": 0,
                    },
                )
            )
        elif (
            attachment.content
            and attachment.size_bytes > 0
            and abs(attachment.size_bytes - len(attachment.content)) > 1024
        ):
            evidence.append(
                ToolEvidence(
                    category="attachment_metadata",
                    detail=(
                        f"Attachment '{filename or 'unnamed'}' declared size ({attachment.size_bytes}) "
                        f"mismatches actual content length ({len(attachment.content)})."
                    ),
                    metadata={
                        "severity": "medium",
                        "confidence": 0.95,
                        "declared_size": attachment.size_bytes,
                        "actual_size": len(attachment.content),
                    },
                )
            )

        # 4. Unsupported or suspicious MIME type prefix
        if any(content_type.startswith(p) for p in UNSUPPORTED_MIME_PREFIXES):
            evidence.append(
                ToolEvidence(
                    category="attachment_metadata",
                    detail=(
                        f"Attachment '{filename or 'unnamed'}' has restricted MIME type '{content_type}'."
                    ),
                    metadata={
                        "severity": "high",
                        "confidence": 0.85,
                        "content_type": content_type,
                    },
                )
            )

        return evidence
