"""Optional YARA adapter for the existing attachment analyzer chain."""

from __future__ import annotations

from typing import Protocol

from src.analyzers.agent.attachments.base import IAttachmentAnalyzer
from src.analyzers.agent.attachments.models import AttachmentPayload
from src.models.agent import ToolEvidence


class IYaraScanner(Protocol):
    """Minimal injectable contract for a configured YARA implementation."""

    def scan(self, attachment: AttachmentPayload) -> tuple[str, ...]:
        """Return matching rule names for the supplied attachment."""


class YaraRuleAnalyzer(IAttachmentAnalyzer):
    """Translate injected YARA matches into canonical attachment evidence."""

    def __init__(self, scanner: IYaraScanner) -> None:
        self._scanner = scanner

    def analyze(self, attachment: AttachmentPayload) -> list[ToolEvidence]:
        return [
            ToolEvidence(
                category="attachment_yara",
                detail=(
                    f"YARA rule '{rule_name}' matched attachment "
                    f"'{attachment.filename}'."
                ),
                metadata={
                    "severity": "high",
                    "confidence": 0.95,
                    "filename": attachment.filename,
                    "rule_name": rule_name,
                },
            )
            for rule_name in self._scanner.scan(attachment)
        ]
