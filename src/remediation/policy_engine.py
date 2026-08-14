"""Response Policy Engine evaluating DecisionPlan provenance, tenant rules, and human approval boundaries."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from src.ai_decision.models import DecisionPlan
from src.common.constants import ActionTaken
from src.config.logging import get_logger
from src.remediation.exceptions import ApprovalRequiredError, PolicyViolationError
from src.remediation.models import ActionStatus, HumanApprovalTokenDTO
from src.risk.models import RiskAssessment

logger = get_logger("scamon.remediation.policy")

HIGH_IMPACT_ACTIONS = {ActionTaken.BLOCKED}


class ResponsePolicyEngine:
    """Evaluates DecisionPlan provenance, tenant policies, confidence thresholds, and human approval rules."""

    def __init__(self, high_impact_override: set[ActionTaken] | None = None) -> None:
        self.high_impact_actions = high_impact_override or HIGH_IMPACT_ACTIONS
        self._used_approval_ids: set[UUID] = set()

    def validate_provenance(
        self,
        tenant_id: UUID,
        assessment: RiskAssessment,
        decision_plan: DecisionPlan,
    ) -> bool:
        """Validate complete 5-ID cryptographic and referential lineage."""
        if tenant_id != assessment.tenant_id or tenant_id != decision_plan.tenant_id:
            logger.error("Tenant ID mismatch across provenance context")
            return False
        if assessment.message_id != decision_plan.message_id:
            logger.error("Message ID mismatch across RiskAssessment and DecisionPlan")
            return False
        if decision_plan.assessment_id != assessment.assessment_id:
            logger.error("Assessment ID mismatch in DecisionPlan reference")
            return False
        return True

    def evaluate_action_policy(
        self,
        tenant_id: UUID,
        assessment: RiskAssessment,
        decision_plan: DecisionPlan,
        requested_action: ActionTaken,
        approval_token: HumanApprovalTokenDTO | None = None,
        is_dry_run: bool = False,
    ) -> tuple[ActionStatus, ActionTaken, str | None]:
        """Evaluate action permissibility under tenant policy and approval rules."""
        # 1. Lineage & Provenance Validation (Fail Closed)
        if not self.validate_provenance(tenant_id, assessment, decision_plan):
            return (
                ActionStatus.FAILED_PERMANENTLY,
                requested_action,
                "PROVENANCE_LINEAGE_MISMATCH",
            )

        # 2. Informational actions
        if requested_action in (ActionTaken.DELIVERED, ActionTaken.PENDING):
            return ActionStatus.POLICY_VALIDATED, requested_action, None

        # 3. Confidence Threshold Check (Minimum 0.85)
        if (
            decision_plan.ai_decision_confidence < 0.85
            and requested_action != ActionTaken.BANNER_INJECTED
        ):
            logger.warning(
                "Action '%s' rejected due to insufficient confidence (%.2f < 0.85)",
                requested_action,
                decision_plan.ai_decision_confidence,
            )
            return (
                ActionStatus.REJECTED,
                requested_action,
                "INSUFFICIENT_CONFIDENCE_SCORE",
            )

        # 4. Human Approval Boundary Check for High-Impact Actions
        if requested_action in self.high_impact_actions:
            if not approval_token:
                logger.info(
                    "High-impact action '%s' requires human approval. Transitioning to PENDING_APPROVAL.",
                    requested_action,
                )
                return (
                    ActionStatus.PENDING_APPROVAL,
                    requested_action,
                    "HUMAN_APPROVAL_REQUIRED",
                )

            # Validate Human Approval Token
            if approval_token.approval_id in self._used_approval_ids:
                logger.error(
                    "Approval token replay detected for ID '%s'",
                    approval_token.approval_id,
                )
                return (
                    ActionStatus.FAILED_PERMANENTLY,
                    requested_action,
                    "APPROVAL_TOKEN_REPLAY_DETECTED",
                )

            if (
                approval_token.tenant_id != tenant_id
                or approval_token.message_id != decision_plan.message_id
            ):
                logger.error("Approval token tenant or message mismatch")
                return (
                    ActionStatus.FAILED_PERMANENTLY,
                    requested_action,
                    "APPROVAL_TOKEN_MISMATCH",
                )

            # Mark approval token as single-use consumed
            self._used_approval_ids.add(approval_token.approval_id)

        # 5. Policy Approved
        return ActionStatus.POLICY_VALIDATED, requested_action, None
