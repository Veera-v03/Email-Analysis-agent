"""Reputation interface for attachment security checks."""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.analyzers.agent.attachments.models import (
    AttachmentReputationResult,
    ReputationStatus,
)


class IAttachmentReputationProvider(ABC):
    """Abstract interface for checking attachment hash reputation."""

    @abstractmethod
    def check_hash(self, sha256_hash: str) -> AttachmentReputationResult:
        """Check reputation for a given SHA-256 hash."""


class NullAttachmentReputationProvider(IAttachmentReputationProvider):
    """Deterministic offline fallback implementation returning unknown status."""

    def check_hash(self, sha256_hash: str) -> AttachmentReputationResult:
        """Return a deterministic unknown result without external network calls."""
        return AttachmentReputationResult(
            sha256=sha256_hash,
            status=ReputationStatus.UNKNOWN,
            score=0.0,
            details={"provider": "NullAttachmentReputationProvider", "mode": "offline"},
        )
