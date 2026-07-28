"""Hash calculation utility and analyzer for cryptographic attachment signatures."""

from __future__ import annotations

import hashlib

from src.analyzers.agent.attachments.base import IAttachmentAnalyzer
from src.analyzers.agent.attachments.models import AttachmentPayload
from src.models.agent import ToolEvidence


def compute_attachment_hashes(content: bytes) -> tuple[str, str]:
    """Compute SHA-256 and MD5 hex digests for content bytes."""
    if not content:
        return "", ""
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content, usedforsecurity=False).hexdigest()
    return sha256, md5


class AttachmentHashAnalyzer(IAttachmentAnalyzer):
    """Compute SHA-256 and MD5 cryptographic hashes for attachment tracking."""

    def analyze(self, attachment: AttachmentPayload) -> list[ToolEvidence]:
        """Compute cryptographic hashes and return structural evidence."""
        evidence: list[ToolEvidence] = []
        content = attachment.content

        if not content:
            return evidence

        sha256, md5 = compute_attachment_hashes(content)
        filename = attachment.filename or "unnamed"

        evidence.append(
            ToolEvidence(
                category="attachment_hash",
                detail=f"Computed cryptographic hashes for attachment '{filename}'.",
                metadata={
                    "severity": "info",
                    "confidence": 1.0,
                    "sha256": sha256,
                    "md5": md5,
                    "size_bytes": len(content),
                },
            )
        )

        return evidence
