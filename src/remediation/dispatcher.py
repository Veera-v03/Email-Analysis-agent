"""Remediation Dispatcher managing canonical idempotency, adapter routing, state machine transitions, and SIEM exports."""

from __future__ import annotations

import hashlib
import time
from uuid import UUID

from src.ai_decision.models import DecisionPlan
from src.common.constants import ActionTaken
from src.config.logging import get_logger
from src.remediation.adapters.base_adapter import IRemediationAdapter
from src.remediation.adapters.identity_adapter import IdentityAdapter
from src.remediation.adapters.mailbox_adapter import EmailMailboxAdapter
from src.remediation.adapters.network_adapter import NetworkSecurityAdapter
from src.remediation.audit_repository import IAuditRepository, SQLiteAuditRepository
from src.remediation.models import (
    ActionStatus,
    HumanApprovalTokenDTO,
    RemediationResultDTO,
)
from src.remediation.policy_engine import ResponsePolicyEngine
from src.remediation.siem_exporter import SIEMIntegrationEngine
from src.risk.models import RiskAssessment

logger = get_logger("scamon.remediation.dispatcher")


class RemediationDispatcher:
    """Orchestrates 12-state remediation lifecycle, canonical idempotency, adapter dispatch, and SIEM exports."""

    def __init__(
        self,
        policy_engine: ResponsePolicyEngine | None = None,
        audit_repo: IAuditRepository | None = None,
        siem_exporter: SIEMIntegrationEngine | None = None,
        adapters: list[IRemediationAdapter] | None = None,
    ) -> None:
        self.policy_engine = policy_engine or ResponsePolicyEngine()
        self.audit_repo = audit_repo or SQLiteAuditRepository()
        self.siem_exporter = siem_exporter or SIEMIntegrationEngine()
        self.adapters = adapters or [
            EmailMailboxAdapter(),
            IdentityAdapter(),
            NetworkSecurityAdapter(),
        ]

    def generate_idempotency_key(
        self,
        tenant_id: UUID,
        incident_id: UUID,
        target_type: str,
        target_id: str,
        action_type: ActionTaken,
        policy_version: str = "1.0.0",
    ) -> str:
        """Compute SHA256 canonical idempotency key."""
        canonical_str = f"{tenant_id}:{incident_id}:{target_type}:{target_id}:{action_type}:{policy_version}"
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def dispatch_remediation(
        self,
        tenant_id: UUID,
        incident_id: UUID,
        assessment: RiskAssessment,
        decision_plan: DecisionPlan,
        requested_action: ActionTaken,
        target_id: str = "default_recipient",
        approval_token: HumanApprovalTokenDTO | None = None,
        is_dry_run: bool = False,
    ) -> RemediationResultDTO:
        """Execute 12-state remediation workflow."""
        start_time = time.perf_counter()

        # 1. Generate Canonical SHA256 Idempotency Key
        idempotency_key = self.generate_idempotency_key(
            tenant_id=tenant_id,
            incident_id=incident_id,
            target_type="mailbox"
            if requested_action != ActionTaken.BLOCKED
            else "network",
            target_id=target_id,
            action_type=requested_action,
        )

        # 2. Check Idempotency in Audit Repository
        cached_result = self.audit_repo.get_remediation_by_idempotency_key(
            tenant_id=str(tenant_id), idempotency_key=idempotency_key
        )
        if cached_result and cached_result.action_status in (
            ActionStatus.VERIFIED,
            ActionStatus.EXECUTED,
        ):
            logger.info(
                "Idempotency match for key '%s'. Returning cached result.",
                idempotency_key,
            )
            return cached_result

        # Initialize Result DTO in REQUESTED State
        result_dto = RemediationResultDTO(
            tenant_id=tenant_id,
            incident_id=incident_id,
            message_id=assessment.message_id,
            assessment_id=assessment.assessment_id,
            decision_plan_id=decision_plan.plan_id,
            requested_action=requested_action,
            approved_action=requested_action,
            action_status=ActionStatus.REQUESTED,
            idempotency_key=idempotency_key,
            executing_adapter="None",
            is_dry_run=is_dry_run,
        )

        # 3. Policy & Lineage Validation
        status, approved_act, failure_msg = self.policy_engine.evaluate_action_policy(
            tenant_id=tenant_id,
            assessment=assessment,
            decision_plan=decision_plan,
            requested_action=requested_action,
            approval_token=approval_token,
            is_dry_run=is_dry_run,
        )

        result_dto.action_status = status
        result_dto.approved_action = approved_act

        if status in (
            ActionStatus.REJECTED,
            ActionStatus.FAILED_PERMANENTLY,
            ActionStatus.PENDING_APPROVAL,
        ):
            result_dto.failure_reason = failure_msg
            self.audit_repo.save_remediation_audit(result_dto)
            result_dto.execution_time_ms = (time.perf_counter() - start_time) * 1000.0
            return result_dto

        # 4. Dry-Run Boundary Enforcement
        if is_dry_run:
            result_dto.action_status = ActionStatus.VERIFIED
            result_dto.executing_adapter = "DryRunAdapter"
            result_dto.external_reference_id = f"dry_run_{idempotency_key[:8]}"
            result_dto.verification_status = "DRY_RUN_SIMULATED"
            result_dto.siem_export_status = self.siem_exporter.export_siem_event(
                result_dto
            )
            self.audit_repo.save_remediation_audit(result_dto)
            result_dto.execution_time_ms = (time.perf_counter() - start_time) * 1000.0
            return result_dto

        # 5. Select Adapter Plugin
        selected_adapter: IRemediationAdapter | None = None
        for adapter in self.adapters:
            if adapter.supports_action(approved_act):
                selected_adapter = adapter
                break

        if not selected_adapter:
            result_dto.action_status = ActionStatus.FAILED_PERMANENTLY
            result_dto.failure_reason = f"NO_ADAPTER_FOR_ACTION_{approved_act}"
            self.audit_repo.save_remediation_audit(result_dto)
            result_dto.execution_time_ms = (time.perf_counter() - start_time) * 1000.0
            return result_dto

        result_dto.executing_adapter = selected_adapter.adapter_name
        result_dto.action_status = ActionStatus.DISPATCHING

        # 6. Dispatch Execution
        success, ref_id, err_msg = selected_adapter.execute_action(
            result_dto=result_dto,
            target_id=target_id,
            is_dry_run=is_dry_run,
        )

        if not success:
            result_dto.action_status = ActionStatus.FAILED
            result_dto.failure_reason = err_msg or "ADAPTER_EXECUTION_FAILED"
            self.audit_repo.save_remediation_audit(result_dto)
            result_dto.execution_time_ms = (time.perf_counter() - start_time) * 1000.0
            return result_dto

        result_dto.action_status = ActionStatus.EXECUTED
        result_dto.external_reference_id = ref_id

        # 7. Response Verification Stage
        result_dto.action_status = ActionStatus.VERIFYING
        verified_ok, ver_msg = selected_adapter.verify_action(
            result_dto=result_dto,
            external_reference_id=ref_id,
        )

        if verified_ok:
            result_dto.action_status = ActionStatus.VERIFIED
            result_dto.verification_status = ver_msg
        else:
            result_dto.action_status = ActionStatus.FAILED
            result_dto.verification_status = "VERIFICATION_FAILED"
            result_dto.failure_reason = ver_msg

        # 8. SIEM Export (Isolated from Remediation Outcome)
        result_dto.siem_export_status = self.siem_exporter.export_siem_event(result_dto)

        # 9. Commit Audit Log
        self.audit_repo.save_remediation_audit(result_dto)

        result_dto.execution_time_ms = (time.perf_counter() - start_time) * 1000.0
        return result_dto
