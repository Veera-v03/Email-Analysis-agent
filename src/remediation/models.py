"""Remediation models, 12-state ActionStatus state machine, and DTO schemas."""

from __future__ import annotations

from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import ConfigDict, Field

from src.common.constants import ActionTaken
from src.common.models import BaseDTO


class ActionStatus(StrEnum):
    """12-State Explicit Remediation Lifecycle State Machine."""

    REQUESTED = "REQUESTED"
    POLICY_VALIDATED = "POLICY_VALIDATED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    DISPATCHING = "DISPATCHING"
    EXECUTED = "EXECUTED"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    RETRYING = "RETRYING"
    FAILED_PERMANENTLY = "FAILED_PERMANENTLY"


class HumanApprovalTokenDTO(BaseDTO):
    """Single-use, non-reusable human authorization token binding."""

    approval_id: UUID = Field(
        default_factory=uuid4, description="Unique single-use approval UUID"
    )
    tenant_id: UUID = Field(description="Associated Tenant UUID")
    incident_id: UUID = Field(description="Associated Incident UUID")
    message_id: str = Field(description="Associated Message ID")
    requested_action: ActionTaken = Field(description="Approved action")
    target_id: str = Field(description="Target recipient, user, or IP")
    approver_identity: str = Field(description="Authorized SOC analyst username")
    created_at: str = Field(description="ISO creation timestamp")
    expires_at: str = Field(description="ISO expiration timestamp")
    is_used: bool = Field(default=False, description="Single-use status flag")


class NetworkBlockRequestDTO(BaseDTO):
    """Typed allowlisted request model for network security block actions."""

    target_type: str = Field(description="IP, DOMAIN, CIDR")
    target_value: str = Field(
        description="Validated target value (e.g. 93.184.216.34 or phish.com)"
    )
    vendor_type: str = Field(description="PALO_ALTO, FORTINET, AWS_WAF")
    rule_name: str = Field(default="ScamON_AutoBlock_Rule")


class RemediationResultDTO(BaseDTO):
    """Universal output object representing complete remediation execution and audit status."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=False)

    remediation_id: UUID = Field(
        default_factory=uuid4, description="Unique remediation run UUID"
    )
    tenant_id: UUID = Field(description="Associated Tenant UUID")
    incident_id: UUID = Field(description="Associated Incident UUID")
    message_id: str = Field(description="Provider message ID")
    assessment_id: UUID = Field(description="Parent RiskAssessment UUID reference")
    decision_plan_id: UUID = Field(description="Parent DecisionPlan UUID reference")
    requested_action: ActionTaken = Field(description="Requested security action")
    approved_action: ActionTaken = Field(
        description="Approved action after policy check"
    )
    action_status: ActionStatus = Field(
        default=ActionStatus.REQUESTED, description="12-State lifecycle status"
    )
    idempotency_key: str = Field(description="SHA256 canonical idempotency hash")
    executing_adapter: str = Field(description="Name of executing adapter plugin")
    external_reference_id: str | None = Field(
        default=None, description="External reference/tracking ID"
    )
    verification_status: str = Field(
        default="PENDING", description="VERIFIED_SUCCESS, PENDING, FAILED"
    )
    audit_status: str = Field(default="PENDING", description="COMMITTED, PENDING")
    siem_export_status: str = Field(
        default="NOT_ATTEMPTED",
        description="SIEM_EXPORTED, SIEM_EXPORT_FAILED, NOT_ATTEMPTED",
    )
    is_dry_run: bool = Field(default=False, description="Dry-run simulation flag")
    execution_time_ms: float = Field(
        default=0.0, description="Remediation execution time in ms"
    )
    failure_reason: str | None = Field(
        default=None, description="Failure error details"
    )
