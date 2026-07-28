"""Entropy calculation analyzer for detecting packed or encrypted payloads."""

from __future__ import annotations

import math
from collections import Counter

from src.analyzers.agent.attachments.base import IAttachmentAnalyzer
from src.analyzers.agent.attachments.models import AttachmentPayload
from src.models.agent import ToolEvidence


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data, returning a score from 0.0 to 8.0."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class AttachmentEntropyAnalyzer(IAttachmentAnalyzer):
    """Calculate Shannon entropy of attachment content bytes to detect packing or encryption."""

    def analyze(self, attachment: AttachmentPayload) -> list[ToolEvidence]:
        """Analyze attachment entropy and report suspicious packing/encryption."""
        evidence: list[ToolEvidence] = []
        content = attachment.content

        if not content or len(content) < 32:
            return evidence

        entropy = calculate_shannon_entropy(content)
        filename = attachment.filename or "unnamed"

        # Report high entropy (> 7.2 out of 8.0)
        if entropy > 7.2:
            evidence.append(
                ToolEvidence(
                    category="attachment_entropy",
                    detail=(
                        f"Attachment '{filename}' has high Shannon entropy ({entropy:.2f} / 8.0), "
                        "indicating packed, encrypted, or highly compressed binary content."
                    ),
                    metadata={
                        "severity": "medium",
                        "confidence": 0.85,
                        "entropy": entropy,
                        "content_length": len(content),
                    },
                )
            )

        return evidence
