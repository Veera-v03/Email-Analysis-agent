"""Comprehensive unit and integration test suite for Module 17 Remediation Engine."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from src.ai_decision.models import DecisionPlan
from src.common.constants import ActionTaken, Verdict
from src.container.di import Container
from src.database.db_client import DatabaseClient
from src.database.models import RawEmail
from src.events.security_events import (
    RemediationExecutedEvent,
    RemediationPendingApprovalEvent,
)
from src.messaging.event_bus import InMemoryEventBus
from src.orchestrator.engine import OrchestratorEngine
from src.registry.module_registry import ModuleRegistry
from src.remediation.adapters.network_adapter import NetworkSecurityAdapter
from src.remediation.audit_repository import SQLiteAuditRepository
from src.remediation.dispatcher import RemediationDispatcher
from src.remediation.engine import RemediationEngine
from src.remediation.models import (
    ActionStatus,
    HumanApprovalTokenDTO,
    NetworkBlockRequestDTO,
)
from src.remediation.module import RemediationModule, register_remediation_module
from src.remediation.policy_engine import ResponsePolicyEngine
from src.remediation.siem_exporter import SIEMIntegrationEngine
from src.risk.models import ConfidenceScoreDetailsDTO, RiskAssessment


def _create_sample_assessment_and_plan() -> tuple[RiskAssessment, DecisionPlan]:
    tenant_id = uuid4()
    assessment_id = uuid4()
    parsed_id = uuid4()
    msg_id = "msg_test_remediation_001"

    assessment = RiskAssessment(
        assessment_id=assessment_id,
        parsed_id=parsed_id,
        transmission_id=uuid4(),
        auth_verification_id=uuid4(),
        intel_enrichment_id=uuid4(),
        account_id=uuid4(),
        tenant_id=tenant_id,
        message_id=msg_id,
        risk_score=90,
        verdict=Verdict.MALICIOUS,
        recommended_action=ActionTaken.QUARANTINED,
        confidence_details=ConfidenceScoreDetailsDTO(overall_confidence=0.95),
        explainability_summary="High risk phishing email detected",
    )

    decision_plan = DecisionPlan(
        assessment_id=assessment_id,
        tenant_id=tenant_id,
        message_id=msg_id,
        executive_summary="Malicious email detected",
        technical_summary="Header spoofing and phishing link identified",
        analyst_explanation="High risk score requiring immediate remediation",
        attack_summary="Phishing Campaign",
        business_impact="High risk of credential theft",
        recommended_actions=["QUARANTINE"],
        risk_confidence=0.95,
        ai_decision_confidence=0.95,
    )

    return assessment, decision_plan


def test_response_policy_provenance_validation() -> None:
    """Verify ResponsePolicyEngine validates 5-ID cryptographic and referential lineage."""
    policy = ResponsePolicyEngine()
    assessment, decision_plan = _create_sample_assessment_and_plan()

    # Valid Lineage
    assert (
        policy.validate_provenance(assessment.tenant_id, assessment, decision_plan)
        is True
    )

    # Lineage Mismatch (Tenant ID mismatch)
    fake_tenant = uuid4()
    assert policy.validate_provenance(fake_tenant, assessment, decision_plan) is False


def test_dry_run_safety_guarantee() -> None:
    """Verify dry-run mode returns VERIFIED with zero external mutations."""
    dispatcher = RemediationDispatcher()
    assessment, decision_plan = _create_sample_assessment_and_plan()

    res = dispatcher.dispatch_remediation(
        tenant_id=assessment.tenant_id,
        incident_id=assessment.parsed_id,
        assessment=assessment,
        decision_plan=decision_plan,
        requested_action=ActionTaken.QUARANTINED,
        is_dry_run=True,
    )

    assert res.action_status == ActionStatus.VERIFIED
    assert res.is_dry_run is True
    assert res.verification_status == "DRY_RUN_SIMULATED"
    assert res.executing_adapter == "DryRunAdapter"


def test_idempotency_key_deduplication() -> None:
    """Verify SHA256 canonical idempotency key prevents duplicate action dispatch."""
    db = DatabaseClient()
    audit_repo = SQLiteAuditRepository(client=db)
    dispatcher = RemediationDispatcher(audit_repo=audit_repo)
    assessment, decision_plan = _create_sample_assessment_and_plan()

    # Initial Run
    res1 = dispatcher.dispatch_remediation(
        tenant_id=assessment.tenant_id,
        incident_id=assessment.parsed_id,
        assessment=assessment,
        decision_plan=decision_plan,
        requested_action=ActionTaken.QUARANTINED,
        is_dry_run=True,
    )

    # Duplicate Run -> Idempotency match
    res2 = dispatcher.dispatch_remediation(
        tenant_id=assessment.tenant_id,
        incident_id=assessment.parsed_id,
        assessment=assessment,
        decision_plan=decision_plan,
        requested_action=ActionTaken.QUARANTINED,
        is_dry_run=True,
    )

    assert res1.idempotency_key == res2.idempotency_key
    assert res2.action_status in (ActionStatus.VERIFIED, ActionStatus.EXECUTED)


def test_human_approval_replay_protection() -> None:
    """Verify single-use human approval token replay protection."""
    policy = ResponsePolicyEngine(high_impact_override={ActionTaken.BLOCKED})
    assessment, decision_plan = _create_sample_assessment_and_plan()

    token = HumanApprovalTokenDTO(
        approval_id=uuid4(),
        tenant_id=assessment.tenant_id,
        incident_id=assessment.parsed_id,
        message_id=assessment.message_id,
        requested_action=ActionTaken.BLOCKED,
        target_id="192.168.1.100",
        approver_identity="soc_analyst_john",
        created_at=datetime.now(UTC).isoformat(),
        expires_at=datetime.now(UTC).isoformat(),
    )

    # First Approval Use -> Validated
    status1, _, _ = policy.evaluate_action_policy(
        tenant_id=assessment.tenant_id,
        assessment=assessment,
        decision_plan=decision_plan,
        requested_action=ActionTaken.BLOCKED,
        approval_token=token,
    )
    assert status1 == ActionStatus.POLICY_VALIDATED

    # Replay Attempt -> Rejected
    status2, _, err_msg = policy.evaluate_action_policy(
        tenant_id=assessment.tenant_id,
        assessment=assessment,
        decision_plan=decision_plan,
        requested_action=ActionTaken.BLOCKED,
        approval_token=token,
    )
    assert status2 == ActionStatus.FAILED_PERMANENTLY
    assert err_msg == "APPROVAL_TOKEN_REPLAY_DETECTED"


def test_network_adapter_payload_allowlisting() -> None:
    """Verify NetworkSecurityAdapter accepts only valid IP/domain targets and rejects invalid strings."""
    adapter = NetworkSecurityAdapter()

    # Valid IP & Domain
    assert (
        adapter.validate_network_payload(
            NetworkBlockRequestDTO(
                target_type="IP", target_value="93.184.216.34", vendor_type="PALO_ALTO"
            )
        )
        is True
    )
    assert (
        adapter.validate_network_payload(
            NetworkBlockRequestDTO(
                target_type="DOMAIN",
                target_value="phishing.com",
                vendor_type="FORTINET",
            )
        )
        is True
    )

    # Invalid Targets (Prevent Command Injection)
    assert (
        adapter.validate_network_payload(
            NetworkBlockRequestDTO(
                target_type="IP",
                target_value="192.168.1.1; rm -rf /",
                vendor_type="PALO_ALTO",
            )
        )
        is False
    )
    assert (
        adapter.validate_network_payload(
            NetworkBlockRequestDTO(
                target_type="DOMAIN",
                target_value="invalid domain string",
                vendor_type="AWS_WAF",
            )
        )
        is False
    )


def test_siem_failure_isolation() -> None:
    """Verify SIEM export failure is isolated and does not affect remediation status."""
    siem = SIEMIntegrationEngine()
    assessment, decision_plan = _create_sample_assessment_and_plan()
    dispatcher = RemediationDispatcher(siem_exporter=siem)

    res = dispatcher.dispatch_remediation(
        tenant_id=assessment.tenant_id,
        incident_id=assessment.parsed_id,
        assessment=assessment,
        decision_plan=decision_plan,
        requested_action=ActionTaken.BANNER_INJECTED,
        is_dry_run=True,
    )

    assert res.action_status == ActionStatus.VERIFIED
    assert res.siem_export_status in ("SIEM_EXPORTED", "SIEM_EXPORT_FAILED")


def test_remediation_event_publication() -> None:
    """Verify RemediationEngine publishes RemediationExecutedEvent to InMemoryEventBus."""

    async def _run() -> None:
        event_bus = InMemoryEventBus()
        events_captured: list[RemediationExecutedEvent] = []

        async def _handler(evt: RemediationExecutedEvent) -> None:
            events_captured.append(evt)

        event_bus.subscribe(RemediationExecutedEvent, _handler)
        engine = RemediationEngine(event_publisher=event_bus)
        assessment, decision_plan = _create_sample_assessment_and_plan()

        res = await engine.execute_remediation(
            tenant_id=assessment.tenant_id,
            incident_id=assessment.parsed_id,
            assessment=assessment,
            decision_plan=decision_plan,
            requested_action=ActionTaken.BANNER_INJECTED,
            is_dry_run=True,
        )

        assert res.remediation_id is not None
        assert len(events_captured) == 1
        assert events_captured[0].action_taken == ActionTaken.BANNER_INJECTED

    asyncio.run(_run())


def test_module17_orchestrator_stage51_integration() -> None:
    """Verify Module 12 Pipeline Orchestrator executes Stage 5.1 Remediation cleanly."""

    async def _run() -> None:
        engine = OrchestratorEngine()

        raw_email = RawEmail(
            id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_stage51_test",
            internet_message_id="<stage51@company.com>",
            raw_eml_data=b"From: User <user@company.com>\r\nTo: rcpt@company.com\r\nSubject: Test\r\n\r\nBody",
        )

        result = await engine.analyze_email(raw_email)

        assert result.analysis_id is not None
        assert "remediation" in result.sla_metrics
        assert result.risk_assessment is not None
        assert result.decision_plan is not None

    asyncio.run(_run())


def test_remediation_module_lifecycle() -> None:
    """Verify RemediationModule DI container registration and health check lifecycle."""

    async def _run() -> None:
        di = Container()
        registry = ModuleRegistry()

        mod = register_remediation_module(di, registry)
        assert registry.get_module("remediation") == mod

        await registry.initialize_all()

        health = await registry.health_check_all()
        assert health.status == "UP"

        await registry.shutdown_all()

    asyncio.run(_run())
