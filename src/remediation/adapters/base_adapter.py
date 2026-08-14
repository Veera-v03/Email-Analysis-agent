"""Abstract base interface for remediation action adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.common.constants import ActionTaken
from src.remediation.models import RemediationResultDTO


class IRemediationAdapter(ABC):
    """Abstract interface for all security action execution adapters."""

    @property
    @abstractmethod
    def adapter_name(self) -> str:
        """Name of adapter plugin."""

    @abstractmethod
    def supports_action(self, action: ActionTaken) -> bool:
        """Return True if adapter handles specified action type."""

    @abstractmethod
    def execute_action(
        self,
        result_dto: RemediationResultDTO,
        target_id: str,
        is_dry_run: bool = False,
    ) -> tuple[bool, str | None, str | None]:
        """Execute remediation action. Returns tuple of (success, external_reference_id, failure_reason)."""

    @abstractmethod
    def verify_action(
        self,
        result_dto: RemediationResultDTO,
        external_reference_id: str | None,
    ) -> tuple[bool, str]:
        """Verify action completion. Returns tuple of (verified_success, status_message)."""
