"""Targeted unit, contract, resilience, and HITL safety tests for Production Hardening Phase 3 (Enterprise Remediation)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock
from uuid import uuid4

import httpx
import pytest

from src.ai_decision.models import DecisionPlan
from src.common.constants import ActionTaken, Verdict
from src.common.redis_client import (
    DistributedRateLimiter,
    InMemoryRedisClient,
)
from src.remediation.adapters.msgraph_adapter import (
    MicrosoftGraphRemediationAdapter,
)
from src.remediation.adapters.panos_adapter import PaloAltoPANOSAdapter
from src.remediation.dispatcher import RemediationDispatcher
from src.remediation.models import (
    ActionStatus,
    HumanApprovalTokenDTO,
    RemediationResultDTO,
)
from src.remediation.policy_engine import ResponsePolicyEngine
from src.risk.models import ConfidenceScoreDetailsDTO, RiskAssessment
from src.threat_intel.resilience.circuit_breaker import (
    CircuitState,
    ProviderCircuitBreaker,
)


# ===========================================================================
# Helper Fixtures & Objects
# ===========================================================================
def create_test_provenance() -> tuple[uuid4, uuid4, RiskAssessment, DecisionPlan]:
    tenant_id = uuid4()
    incident_id = uuid4()
    assessment_id = uuid4()
    plan_id = uuid4()
    msg_id = "<alert-threat-999@corp.local>"

    assessment = RiskAssessment(
        assessment_id=assessment_id,
        tenant_id=tenant_id,
        parsed_id=uuid4(),
        transmission_id=uuid4(),
        auth_verification_id=uuid4(),
        intel_enrichment_id=uuid4(),
        account_id=uuid4(),
        message_id=msg_id,
        risk_score=95,
        verdict=Verdict.MALICIOUS,
        recommended_action=ActionTaken.QUARANTINED,
        confidence_details=ConfidenceScoreDetailsDTO(overall_confidence=0.95),
        explainability_summary="High confidence malicious email",
    )

    decision_plan = DecisionPlan(
        plan_id=plan_id,
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        message_id=msg_id,
        executive_summary="Executive summary: malicious phishing attempt",
        technical_summary="Technical summary: SPF pass, malicious URL detected",
        analyst_explanation="Detailed analyst explanation of phishing attack",
        attack_summary="Credential harvesting attack vector",
        business_impact="Potential credential compromise",
        risk_confidence=0.95,
        ai_decision_confidence=0.95,
    )

    return tenant_id, incident_id, assessment, decision_plan


# ===========================================================================
# 1. Microsoft Graph Adapter Tests
# ===========================================================================
def test_msgraph_oauth_token_acquisition_and_caching() -> None:
    mock_token_resp = httpx.Response(
        status_code=200,
        json={"access_token": "mock_secret_token_12345", "expires_in": 3600},
        request=httpx.Request("POST", "https://login.microsoftonline.com/dummy/oauth2/v2.0/token"),
    )
    mock_action_resp = httpx.Response(
        status_code=201,
        json={"id": "new_msg_id", "isRead": True},
        request=httpx.Request("POST", "https://graph.microsoft.com/v1.0/users/user@corp.com/messages/msg1/move"),
    )

    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.side_effect = [mock_token_resp, mock_action_resp, mock_action_resp]

    adapter = MicrosoftGraphRemediationAdapter(
        tenant_id="tenant-123",
        client_id="client-456",
        client_secret="secret-789",
        http_client=mock_client,
    )

    dto = RemediationResultDTO(
        tenant_id=uuid4(),
        incident_id=uuid4(),
        message_id="<msg-12345@corp.local>",
        assessment_id=uuid4(),
        decision_plan_id=uuid4(),
        requested_action=ActionTaken.QUARANTINED,
        approved_action=ActionTaken.QUARANTINED,
        idempotency_key="hash_123",
        executing_adapter="MicrosoftGraphRemediationAdapter",
    )

    # 1. First execution acquires token and moves message
    success_1, ref_1, err_1 = adapter.execute_action(dto, "target_user@corp.com")
    assert success_1 is True
    assert ref_1 is not None and ref_1.startswith("msgraph_")
    assert err_1 is None

    # 2. Second execution reuses cached token (only 1 post call for move, 0 for token)
    success_2, ref_2, err_2 = adapter.execute_action(dto, "target_user@corp.com")
    assert success_2 is True
    assert mock_client.post.call_count == 3  # 1 token + 2 moves (token was reused!)


def test_msgraph_dry_run_zero_mutation() -> None:
    mock_client = MagicMock(spec=httpx.Client)
    adapter = MicrosoftGraphRemediationAdapter(
        tenant_id="tenant-123",
        client_id="client-456",
        client_secret="secret-789",
        http_client=mock_client,
    )

    dto = RemediationResultDTO(
        tenant_id=uuid4(),
        incident_id=uuid4(),
        message_id="<msg-dryrun@corp.local>",
        assessment_id=uuid4(),
        decision_plan_id=uuid4(),
        requested_action=ActionTaken.QUARANTINED,
        approved_action=ActionTaken.QUARANTINED,
        idempotency_key="hash_dry",
        executing_adapter="MicrosoftGraphRemediationAdapter",
        is_dry_run=True,
    )

    success, ref, err = adapter.execute_action(dto, "user@corp.com", is_dry_run=True)
    assert success is True
    assert ref is not None and ref.startswith("dry_run_msgraph_")
    assert err is None
    # Must NOT have made any network calls!
    assert mock_client.post.call_count == 0


def test_msgraph_404_handled_as_idempotent_success() -> None:
    mock_token_resp = httpx.Response(
        status_code=200,
        json={"access_token": "token_abc", "expires_in": 3600},
        request=httpx.Request("POST", "https://login.microsoftonline.com/dummy/oauth2/v2.0/token"),
    )
    mock_404_resp = httpx.Response(
        status_code=404,
        json={"error": {"code": "ErrorItemNotFound", "message": "Item not found"}},
        request=httpx.Request("POST", "https://graph.microsoft.com/v1.0/messages/msg1/move"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.side_effect = [mock_token_resp, mock_404_resp]

    adapter = MicrosoftGraphRemediationAdapter(
        tenant_id="tenant-123",
        client_id="client-456",
        client_secret="secret-789",
        http_client=mock_client,
    )

    dto = RemediationResultDTO(
        tenant_id=uuid4(),
        incident_id=uuid4(),
        message_id="<already-moved@corp.local>",
        assessment_id=uuid4(),
        decision_plan_id=uuid4(),
        requested_action=ActionTaken.QUARANTINED,
        approved_action=ActionTaken.QUARANTINED,
        idempotency_key="hash_404",
        executing_adapter="MicrosoftGraphRemediationAdapter",
    )

    success, ref, err = adapter.execute_action(dto, "user@corp.com")
    assert success is True
    assert ref is not None
    assert err is None


def test_msgraph_auth_failure_permanent_abort() -> None:
    mock_token_resp = httpx.Response(
        status_code=200,
        json={"access_token": "invalid_scope_token", "expires_in": 3600},
        request=httpx.Request("POST", "https://login.microsoftonline.com/dummy/oauth2/v2.0/token"),
    )
    mock_403_resp = httpx.Response(
        status_code=403,
        json={"error": {"code": "ErrorAccessDenied"}},
        request=httpx.Request("POST", "https://graph.microsoft.com/v1.0/messages/msg1/move"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.side_effect = [mock_token_resp, mock_403_resp]

    adapter = MicrosoftGraphRemediationAdapter(
        tenant_id="tenant-123",
        client_id="client-456",
        client_secret="secret-789",
        http_client=mock_client,
    )

    dto = RemediationResultDTO(
        tenant_id=uuid4(),
        incident_id=uuid4(),
        message_id="<forbidden-msg@corp.local>",
        assessment_id=uuid4(),
        decision_plan_id=uuid4(),
        requested_action=ActionTaken.QUARANTINED,
        approved_action=ActionTaken.QUARANTINED,
        idempotency_key="hash_403",
        executing_adapter="MicrosoftGraphRemediationAdapter",
    )

    success, ref, err = adapter.execute_action(dto, "user@corp.com")
    assert success is False
    assert ref is None
    assert "HTTP_AUTH_FORBIDDEN_403" in str(err)
    # Must have aborted after 1 attempt rather than retrying 403 indefinitely!
    assert mock_client.post.call_count == 2


# ===========================================================================
# 2. Palo Alto PAN-OS Adapter Tests
# ===========================================================================
def test_panos_successful_block_ipv4_and_domain() -> None:
    mock_201_resp = httpx.Response(
        status_code=201,
        json={"@status": "success", "msg": "command succeeded"},
        request=httpx.Request("POST", "https://firewall.local/restapi/v10.0/Objects/Addresses"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.return_value = mock_201_resp

    adapter = PaloAltoPANOSAdapter(
        host="firewall.local",
        api_key="panos_secret_api_key",
        http_client=mock_client,
    )

    dto = RemediationResultDTO(
        tenant_id=uuid4(),
        incident_id=uuid4(),
        message_id="<threat-msg@corp.local>",
        assessment_id=uuid4(),
        decision_plan_id=uuid4(),
        requested_action=ActionTaken.BLOCKED,
        approved_action=ActionTaken.BLOCKED,
        idempotency_key="hash_panos",
        executing_adapter="PaloAltoPANOSAdapter",
    )

    # 1. Block IPv4
    success_ip, ref_ip, _ = adapter.execute_action(dto, "198.51.100.99")
    assert success_ip is True
    assert ref_ip is not None and ref_ip.startswith("panos_rule_")

    # 2. Block Domain
    success_dom, ref_dom, _ = adapter.execute_action(dto, "malicious-domain.com")
    assert success_dom is True
    assert ref_dom is not None


def test_panos_invalid_target_rejected() -> None:
    adapter = PaloAltoPANOSAdapter(host="fw.local", api_key="key")
    dto = RemediationResultDTO(
        tenant_id=uuid4(),
        incident_id=uuid4(),
        message_id="<msg@corp.local>",
        assessment_id=uuid4(),
        decision_plan_id=uuid4(),
        requested_action=ActionTaken.BLOCKED,
        approved_action=ActionTaken.BLOCKED,
        idempotency_key="hash_inv",
        executing_adapter="PaloAltoPANOSAdapter",
    )

    success, ref, err = adapter.execute_action(dto, "invalid; rm -rf /")
    assert success is False
    assert ref is None
    assert "INVALID_NETWORK_TARGET" in str(err)


def test_panos_409_conflict_handled_as_idempotent_success() -> None:
    mock_409_resp = httpx.Response(
        status_code=409,
        json={"@status": "error", "msg": "Object already exists"},
        request=httpx.Request("POST", "https://firewall.local/restapi/v10.0/Objects/Addresses"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.return_value = mock_409_resp

    adapter = PaloAltoPANOSAdapter(
        host="firewall.local",
        api_key="panos_secret_api_key",
        http_client=mock_client,
    )

    dto = RemediationResultDTO(
        tenant_id=uuid4(),
        incident_id=uuid4(),
        message_id="<threat-msg@corp.local>",
        assessment_id=uuid4(),
        decision_plan_id=uuid4(),
        requested_action=ActionTaken.BLOCKED,
        approved_action=ActionTaken.BLOCKED,
        idempotency_key="hash_409",
        executing_adapter="PaloAltoPANOSAdapter",
    )

    success, ref, err = adapter.execute_action(dto, "203.0.113.50")
    assert success is True
    assert ref is not None and "existing" in ref
    assert err is None


# ===========================================================================
# 3. HITL, Provenance & Policy Safety Tests
# ===========================================================================
def test_policy_provenance_lineage_validation() -> None:
    policy_engine = ResponsePolicyEngine()
    tenant_id, incident_id, assessment, decision_plan = create_test_provenance()

    # Provenance matches
    assert policy_engine.validate_provenance(tenant_id, assessment, decision_plan) is True

    # Provenance mismatch (different tenant)
    wrong_tenant = uuid4()
    assert policy_engine.validate_provenance(wrong_tenant, assessment, decision_plan) is False

    # Status evaluates to FAILED_PERMANENTLY on mismatch
    status, _, reason = policy_engine.evaluate_action_policy(
        wrong_tenant, assessment, decision_plan, ActionTaken.QUARANTINED
    )
    assert status == ActionStatus.FAILED_PERMANENTLY
    assert reason == "PROVENANCE_LINEAGE_MISMATCH"


def test_hitl_high_impact_requires_human_approval() -> None:
    policy_engine = ResponsePolicyEngine()
    tenant_id, incident_id, assessment, decision_plan = create_test_provenance()

    # 1. High impact action (BLOCKED) without token -> PENDING_APPROVAL
    status_1, _, reason_1 = policy_engine.evaluate_action_policy(
        tenant_id, assessment, decision_plan, ActionTaken.BLOCKED, approval_token=None
    )
    assert status_1 == ActionStatus.PENDING_APPROVAL
    assert reason_1 == "HUMAN_APPROVAL_REQUIRED"

    # 2. Provide valid HumanApprovalTokenDTO -> POLICY_VALIDATED
    now_iso = datetime.now(UTC).isoformat()
    exp_iso = (datetime.now(UTC) + timedelta(minutes=15)).isoformat()
    token = HumanApprovalTokenDTO(
        tenant_id=tenant_id,
        incident_id=incident_id,
        message_id=assessment.message_id,
        requested_action=ActionTaken.BLOCKED,
        target_id="198.51.100.1",
        approver_identity="soc_analyst_alice",
        created_at=now_iso,
        expires_at=exp_iso,
    )

    status_2, _, reason_2 = policy_engine.evaluate_action_policy(
        tenant_id, assessment, decision_plan, ActionTaken.BLOCKED, approval_token=token
    )
    assert status_2 == ActionStatus.POLICY_VALIDATED
    assert reason_2 is None

    # 3. Single-use replay of same approval token -> FAILED_PERMANENTLY
    status_3, _, reason_3 = policy_engine.evaluate_action_policy(
        tenant_id, assessment, decision_plan, ActionTaken.BLOCKED, approval_token=token
    )
    assert status_3 == ActionStatus.FAILED_PERMANENTLY
    assert reason_3 == "APPROVAL_TOKEN_REPLAY_DETECTED"


def test_remediation_dispatcher_canonical_idempotency() -> None:
    dispatcher = RemediationDispatcher()
    tenant_id, incident_id, assessment, decision_plan = create_test_provenance()

    # 1. Dispatch first remediation
    result_1 = dispatcher.dispatch_remediation(
        tenant_id=tenant_id,
        incident_id=incident_id,
        assessment=assessment,
        decision_plan=decision_plan,
        requested_action=ActionTaken.QUARANTINED,
        target_id="user@corp.local",
    )
    assert result_1.action_status == ActionStatus.VERIFIED

    # 2. Dispatch identical remediation -> Returns cached idempotent result
    result_2 = dispatcher.dispatch_remediation(
        tenant_id=tenant_id,
        incident_id=incident_id,
        assessment=assessment,
        decision_plan=decision_plan,
        requested_action=ActionTaken.QUARANTINED,
        target_id="user@corp.local",
    )
    assert result_2.remediation_id == result_1.remediation_id
    assert result_2.idempotency_key == result_1.idempotency_key
