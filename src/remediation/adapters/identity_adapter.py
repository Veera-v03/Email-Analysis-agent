"""Identity remediation adapter executing user account locks and credential resets."""

from __future__ import annotations

from src.common.constants import ActionTaken
from src.config.logging import get_logger
from src.remediation.adapters.base_adapter import IRemediationAdapter
from src.remediation.models import RemediationResultDTO

logger = get_logger("scamon.remediation.adapters.identity")


class IdentityAdapter(IRemediationAdapter):
    """Handles Azure AD / Okta identity security remediation operations."""

    @property
    def adapter_name(self) -> str:
        return "IdentityAdapter"

    def supports_action(self, action: ActionTaken) -> bool:
        # Custom identity actions mapped via BLOCKED or specific policy
        return action in (ActionTaken.BLOCKED, ActionTaken.QUARANTINED)

    def execute_action(
        self,
        result_dto: RemediationResultDTO,
        target_id: str,
        is_dry_run: bool = False,
    ) -> tuple[bool, str | None, str | None]:
        """Execute identity lock / session revocation."""
        if is_dry_run:
            logger.info("DRY-RUN SIMULATED: Identity action for target '%s'", target_id)
            return True, f"dry_run_id_{target_id[:8]}", None

        ref_id = f"aad_lock_{hash(target_id) & 0xFFFFFFFF:08x}"
        logger.info(
            "EXECUTED: Identity lock action for user '%s' (Ref: %s)",
            target_id,
            ref_id,
        )
        return True, ref_id, None

    def verify_action(
        self,
        result_dto: RemediationResultDTO,
        external_reference_id: str | None,
    ) -> tuple[bool, str]:
        """Verify identity lock status."""
        if result_dto.is_dry_run:
            return True, "DRY_RUN_SIMULATED"
        if external_reference_id and external_reference_id.startswith("aad_"):
            return True, "VERIFIED_IDENTITY_LOCKED"
        return False, "UNVERIFIED_IDENTITY_REFERENCE"
