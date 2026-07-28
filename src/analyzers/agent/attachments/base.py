"""Base contract for internal attachment analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.analyzers.agent.attachments.models import AttachmentPayload
from src.models.agent import ToolEvidence


class IAttachmentAnalyzer(ABC):
    """Define interface for modular attachment analysis components."""

    @abstractmethod
    def analyze(self, attachment: AttachmentPayload) -> list[ToolEvidence]:
        """Analyze an attachment payload and return structured tool evidence."""
