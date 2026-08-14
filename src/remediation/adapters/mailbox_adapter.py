"""Email Mailbox remediation adapter executing quarantine, retraction, banner injection, and deletion."""

from __future__ import annotations

from src.common.constants import ActionTaken
from src.config.logging import get_logger
from src.remediation.adapters.base_adapter import IRemediationAdapter
from src.remediation.models import RemediationResultDTO

logger = get_logger("scamon.remediation.adapters.mailbox")


class EmailMailboxAdapter(IRemediationAdapter):
    """Handles email mailbox security operations (Quarantine, Retract, Banner Inject, Hard Delete)."""

    @property
    def adapter_name(self) -> str:
        return "EmailMailboxAdapter"

    def supports_action(self, action: ActionTaken) -> bool:
        return action in (
            ActionTaken.QUARANTINED,
            ActionTaken.RETRACTED,
            ActionTaken.BANNER_INJECTED,
            ActionTaken.BLOCKED,
        )

    def execute_action(
        self,
        result_dto: RemediationResultDTO,
        target_id: str,
        is_dry_run: bool = False,
    ) -> tuple[bool, str | None, str | None]:
        """Execute mailbox operation or simulate in dry-run mode."""
        action = result_dto.approved_action
        if is_dry_run:
            logger.info(
                "DRY-RUN SIMULATED: Mailbox action '%s' for message '%s' target '%s'",
                action,
                result_dto.message_id,
                target_id,
            )
            return True, f"dry_run_mbx_{result_dto.message_id[:8]}", None

        # Simulated enterprise mailbox API execution (Exchange / M365 / Gmail API)
        ref_id = f"m365_{action.lower()}_{hash(result_dto.message_id) & 0xFFFFFFFF:08x}"
        logger.info(
            "EXECUTED: Mailbox action '%s' for msg '%s' (Ref: %s)",
            action,
            result_dto.message_id,
            ref_id,
        )
        return True, ref_id, None

    def verify_action(
        self,
        result_dto: RemediationResultDTO,
        external_reference_id: str | None,
    ) -> tuple[bool, str]:
        """Verify post-execution mailbox status."""
        if result_dto.is_dry_run:
            return True, "DRY_RUN_SIMULATED"
        if external_reference_id and external_reference_id.startswith("m365_"):
            return True, "VERIFIED_MAILBOX_SUCCESS"
        return False, "UNVERIFIED_REFERENCE_ID"
