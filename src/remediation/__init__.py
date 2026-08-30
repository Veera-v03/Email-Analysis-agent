"""Remediation & Incident Response Package for ScamON Enterprise."""

from __future__ import annotations

from src.remediation.adapters.base_adapter import IRemediationAdapter
from src.remediation.adapters.identity_adapter import IdentityAdapter
from src.remediation.adapters.mailbox_adapter import EmailMailboxAdapter
from src.remediation.adapters.msgraph_adapter import (
    MicrosoftGraphRemediationAdapter,
)
from src.remediation.adapters.network_adapter import NetworkSecurityAdapter
from src.remediation.adapters.panos_adapter import PaloAltoPANOSAdapter
from src.remediation.audit_repository import IAuditRepository, SQLiteAuditRepository
from src.remediation.dispatcher import RemediationDispatcher
from src.remediation.engine import RemediationEngine
from src.remediation.exceptions import (
    ApprovalRequiredError,
    PolicyViolationError,
    RemediationError,
)
from src.remediation.models import (
    ActionStatus,
    HumanApprovalTokenDTO,
    NetworkBlockRequestDTO,
    RemediationResultDTO,
)
from src.remediation.module import RemediationModule, register_remediation_module
from src.remediation.policy_engine import ResponsePolicyEngine
from src.remediation.siem_exporter import SIEMIntegrationEngine

__all__ = [
    "ActionStatus",
    "ApprovalRequiredError",
    "EmailMailboxAdapter",
    "HumanApprovalTokenDTO",
    "IAuditRepository",
    "IRemediationAdapter",
    "IdentityAdapter",
    "MicrosoftGraphRemediationAdapter",
    "NetworkBlockRequestDTO",
    "NetworkSecurityAdapter",
    "PaloAltoPANOSAdapter",
    "PolicyViolationError",
    "RemediationDispatcher",
    "RemediationEngine",
    "RemediationError",
    "RemediationModule",
    "RemediationResultDTO",
    "ResponsePolicyEngine",
    "SIEMIntegrationEngine",
    "SQLiteAuditRepository",
    "register_remediation_module",
]
