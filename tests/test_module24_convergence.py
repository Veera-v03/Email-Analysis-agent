"""Targeted unit and integration tests for Module 24 Phase 3 (TenantMemoryConvergenceEngine & Rollback)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.api.main import app
from src.events.feedback_events import AnalystVerdictSubmittedEvent
from src.feedback.convergence import (
    MAX_CONVERGENCE_DELTA,
    ConvergenceRecordNotFoundError,
    ConvergenceRollbackError,
    ConvergenceUnauthorizedError,
    TenantMemoryConvergenceEngine,
)
from src.feedback.models import (
    AnalystTrustLevel,
    AnalystVerdictCorrection,
    AuthenticatedAnalystDTO,
)
from src.feedback.router import set_convergence_engine
from src.security.auth import create_jwt_token


# ===========================================================================
# 1. Convergence Mathematical Model & Signal Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_false_positive_increases_trust_lead_admin() -> None:
    engine = TenantMemoryConvergenceEngine()
    tenant_id = uuid4()
    feedback_id = uuid4()
    event_id = uuid4()
    entity_key = "sender@legit-vendor.com"

    # Prior trust is 0.50
    res = await engine.apply_convergence(
        tenant_id=tenant_id,
        feedback_id=feedback_id,
        event_id=event_id,
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE.value,
        analyst_trust_level=AnalystTrustLevel.LEAD_SOC_ADMIN.value,
        analyst_id="admin_1",
        entity_key=entity_key,
    )

    assert res.applied is True
    assert res.prior_score == 0.50
    assert res.delta == 0.20  # 0.20 * 1.00 * 1.0 = +0.20
    assert res.posterior_score == 0.70
    assert await engine.get_tenant_entity_trust(tenant_id, entity_key) == 0.70


@pytest.mark.asyncio
async def test_false_negative_decreases_trust_junior_analyst() -> None:
    engine = TenantMemoryConvergenceEngine()
    tenant_id = uuid4()
    feedback_id = uuid4()
    event_id = uuid4()
    entity_key = "attacker@phish.net"

    # Junior trust weight is 0.50 -> delta = 0.20 * 0.50 * (-1.0) = -0.10
    res = await engine.apply_convergence(
        tenant_id=tenant_id,
        feedback_id=feedback_id,
        event_id=event_id,
        corrected_verdict=AnalystVerdictCorrection.FALSE_NEGATIVE.value,
        analyst_trust_level=AnalystTrustLevel.JUNIOR_ANALYST.value,
        analyst_id="junior_1",
        entity_key=entity_key,
    )

    assert res.applied is True
    assert res.prior_score == 0.50
    assert res.delta == -0.10
    assert res.posterior_score == 0.40


@pytest.mark.asyncio
async def test_confirmed_clean_and_confirmed_malicious() -> None:
    engine = TenantMemoryConvergenceEngine()
    t_id = uuid4()

    # Confirmed clean: senior analyst (0.85 weight) -> 0.20 * 0.85 * 0.80 = +0.136
    res_clean = await engine.apply_convergence(
        tenant_id=t_id,
        feedback_id=uuid4(),
        event_id=uuid4(),
        corrected_verdict=AnalystVerdictCorrection.CONFIRMED_CLEAN.value,
        analyst_trust_level=AnalystTrustLevel.SENIOR_ANALYST.value,
        analyst_id="senior_1",
        entity_key="good@news.com",
    )
    assert res_clean.applied is True
    assert round(res_clean.delta, 3) == 0.136
    assert round(res_clean.posterior_score, 3) == 0.636

    # Confirmed malicious: lead analyst (1.00 weight) -> 0.20 * 1.00 * (-1.0) = -0.20
    res_mal = await engine.apply_convergence(
        tenant_id=t_id,
        feedback_id=uuid4(),
        event_id=uuid4(),
        corrected_verdict=AnalystVerdictCorrection.CONFIRMED_MALICIOUS.value,
        analyst_trust_level=AnalystTrustLevel.LEAD_SOC_ADMIN.value,
        analyst_id="lead_1",
        entity_key="evil@c2.com",
    )
    assert res_mal.applied is True
    assert res_mal.delta == -0.20
    assert res_mal.posterior_score == 0.30


@pytest.mark.asyncio
async def test_confirmed_suspicious_and_benign_anomaly() -> None:
    engine = TenantMemoryConvergenceEngine()
    t_id = uuid4()

    # Confirmed suspicious: lead admin (1.00 weight) -> 0.20 * 1.00 * (-0.50) = -0.10
    res_susp = await engine.apply_convergence(
        tenant_id=t_id,
        feedback_id=uuid4(),
        event_id=uuid4(),
        corrected_verdict=AnalystVerdictCorrection.CONFIRMED_SUSPICIOUS.value,
        analyst_trust_level=AnalystTrustLevel.LEAD_SOC_ADMIN.value,
        analyst_id="lead_1",
        entity_key="susp@vendor.com",
    )
    assert res_susp.applied is True
    assert res_susp.delta == -0.10
    assert res_susp.posterior_score == 0.40

    # Benign anomaly: lead admin (1.00 weight) -> 0.20 * 1.00 * 0.40 = +0.08
    res_benign = await engine.apply_convergence(
        tenant_id=t_id,
        feedback_id=uuid4(),
        event_id=uuid4(),
        corrected_verdict=AnalystVerdictCorrection.BENIGN_ANOMALY.value,
        analyst_trust_level=AnalystTrustLevel.LEAD_SOC_ADMIN.value,
        analyst_id="lead_1",
        entity_key="dkim-broken@vendor.com",
    )
    assert res_benign.applied is True
    assert round(res_benign.delta, 2) == 0.08
    assert round(res_benign.posterior_score, 2) == 0.58


@pytest.mark.asyncio
async def test_needs_escalation_zero_delta() -> None:
    engine = TenantMemoryConvergenceEngine()
    t_id = uuid4()
    res = await engine.apply_convergence(
        tenant_id=t_id,
        feedback_id=uuid4(),
        event_id=uuid4(),
        corrected_verdict=AnalystVerdictCorrection.NEEDS_ESCALATION.value,
        analyst_trust_level=AnalystTrustLevel.LEAD_SOC_ADMIN.value,
        analyst_id="lead_1",
        entity_key="unknown@domain.com",
    )
    assert res.applied is True
    assert res.delta == 0.0
    assert res.posterior_score == 0.50


@pytest.mark.asyncio
async def test_delta_bounds_enforced_at_20_percent() -> None:
    engine = TenantMemoryConvergenceEngine()
    t_id = uuid4()
    res = await engine.apply_convergence(
        tenant_id=t_id,
        feedback_id=uuid4(),
        event_id=uuid4(),
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE.value,
        analyst_trust_level=AnalystTrustLevel.LEAD_SOC_ADMIN.value,
        analyst_id="lead_1",
        entity_key="test@domain.com",
    )
    assert -MAX_CONVERGENCE_DELTA <= res.delta <= MAX_CONVERGENCE_DELTA


# ===========================================================================
# 2. Tenant Boundary & Idempotency Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_tenant_isolation_partitioning() -> None:
    engine = TenantMemoryConvergenceEngine()
    tenant_a = uuid4()
    tenant_b = uuid4()
    shared_entity = "payroll@global-vendor.com"

    # Tenant A marks as FALSE_POSITIVE -> trust increases to 0.70
    await engine.apply_convergence(
        tenant_id=tenant_a,
        feedback_id=uuid4(),
        event_id=uuid4(),
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE.value,
        analyst_trust_level=AnalystTrustLevel.LEAD_SOC_ADMIN.value,
        analyst_id="admin_a",
        entity_key=shared_entity,
    )

    # Tenant B trust remains untouched at default 0.50
    trust_a = await engine.get_tenant_entity_trust(tenant_a, shared_entity)
    trust_b = await engine.get_tenant_entity_trust(tenant_b, shared_entity)

    assert trust_a == 0.70
    assert trust_b == 0.50


@pytest.mark.asyncio
async def test_event_idempotency_duplicate_skipped() -> None:
    engine = TenantMemoryConvergenceEngine()
    t_id = uuid4()
    fb_id = uuid4()
    evt_id = uuid4()
    entity = "vendor@test.com"

    res1 = await engine.apply_convergence(
        tenant_id=t_id,
        feedback_id=fb_id,
        event_id=evt_id,
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE.value,
        analyst_trust_level=AnalystTrustLevel.LEAD_SOC_ADMIN.value,
        analyst_id="admin_1",
        entity_key=entity,
    )
    assert res1.applied is True
    assert res1.posterior_score == 0.70

    # Repeat same event
    res2 = await engine.apply_convergence(
        tenant_id=t_id,
        feedback_id=fb_id,
        event_id=evt_id,
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE.value,
        analyst_trust_level=AnalystTrustLevel.LEAD_SOC_ADMIN.value,
        analyst_id="admin_1",
        entity_key=entity,
    )
    assert res2.applied is False
    assert res2.reason == "IDEMPOTENT_DUPLICATE"
    assert res2.posterior_score == 0.70  # Did not double-increment to 0.90!


@pytest.mark.asyncio
async def test_handle_event_subscriber_integration() -> None:
    engine = TenantMemoryConvergenceEngine()
    t_id = uuid4()
    fb_id = uuid4()
    inc_id = uuid4()
    event = AnalystVerdictSubmittedEvent(
        tenant_id=t_id,
        feedback_id=fb_id,
        incident_id=inc_id,
        message_id="msg_0099",
        original_verdict="MALICIOUS",
        corrected_verdict="FALSE_POSITIVE",
        reason_category="AUTHORIZED_EXTERNAL_VENDOR",
        analyst_id="analyst_alice",
        analyst_trust_level="SENIOR_ANALYST",
    )

    res = await engine.handle_event(event)
    assert res.applied is True
    assert res.feedback_id == fb_id
    assert res.tenant_id == t_id


# ===========================================================================
# 3. Rollback & Audit Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_convergence_rollback_restores_prior_score() -> None:
    engine = TenantMemoryConvergenceEngine()
    t_id = uuid4()
    fb_id = uuid4()
    entity = "vendor@test.com"

    # 1. Apply convergence: prior 0.50 -> posterior 0.70
    await engine.apply_convergence(
        tenant_id=t_id,
        feedback_id=fb_id,
        event_id=uuid4(),
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE.value,
        analyst_trust_level=AnalystTrustLevel.LEAD_SOC_ADMIN.value,
        analyst_id="admin_1",
        entity_key=entity,
    )
    assert await engine.get_tenant_entity_trust(t_id, entity) == 0.70

    # 2. Roll back convergence as Admin
    admin_caller = AuthenticatedAnalystDTO(
        analyst_id="lead_admin_bob",
        tenant_id=t_id,
        role="ADMIN",
    )
    rb_res = await engine.rollback_convergence(
        tenant_id=t_id,
        feedback_id=fb_id,
        admin_caller=admin_caller,
    )

    assert rb_res.restored_score == 0.50
    assert rb_res.rolled_back_by == "lead_admin_bob"
    assert await engine.get_tenant_entity_trust(t_id, entity) == 0.50

    # 3. Attempting duplicate rollback raises error
    with pytest.raises(ConvergenceRollbackError):
        await engine.rollback_convergence(t_id, fb_id, admin_caller)


@pytest.mark.asyncio
async def test_rollback_unauthorized_role_rejected() -> None:
    engine = TenantMemoryConvergenceEngine()
    t_id = uuid4()
    fb_id = uuid4()

    junior_caller = AuthenticatedAnalystDTO(
        analyst_id="junior_alice",
        tenant_id=t_id,
        role="ANALYST",
    )

    with pytest.raises(ConvergenceUnauthorizedError):
        await engine.rollback_convergence(t_id, fb_id, junior_caller)


@pytest.mark.asyncio
async def test_rollback_record_not_found() -> None:
    engine = TenantMemoryConvergenceEngine()
    t_id = uuid4()
    admin_caller = AuthenticatedAnalystDTO(
        analyst_id="admin",
        tenant_id=t_id,
        role="ADMIN",
    )
    with pytest.raises(ConvergenceRecordNotFoundError):
        await engine.rollback_convergence(t_id, uuid4(), admin_caller)


@pytest.mark.asyncio
async def test_concurrent_updates_thread_safety() -> None:
    engine = TenantMemoryConvergenceEngine()
    t_id = uuid4()
    entity = "high-volume-sender@vendor.com"

    # Fire 10 concurrent events for the same entity
    async def _send_event(i: int) -> None:
        await engine.apply_convergence(
            tenant_id=t_id,
            feedback_id=uuid4(),
            event_id=uuid4(),
            corrected_verdict=AnalystVerdictCorrection.CONFIRMED_CLEAN.value,
            analyst_trust_level=AnalystTrustLevel.JUNIOR_ANALYST.value,
            analyst_id=f"analyst_{i}",
            entity_key=entity,
        )

    await asyncio.gather(*[_send_event(i) for i in range(10)])

    # All 10 updates were safely applied without loss
    audit_trail = await engine.get_convergence_audit_trail(t_id)
    assert len(audit_trail) == 10
    final_trust = await engine.get_tenant_entity_trust(t_id, entity)
    assert final_trust > 0.50


# ===========================================================================
# 4. FastAPI Rollback Endpoint Integration Tests
# ===========================================================================
def test_api_rollback_endpoint_success() -> None:
    engine = TenantMemoryConvergenceEngine()
    set_convergence_engine(engine)
    client = TestClient(app)

    tenant_id = uuid4()
    feedback_id = uuid4()
    entity = "payroll@company.com"

    # Pre-populate convergence record
    asyncio.run(
        engine.apply_convergence(
            tenant_id=tenant_id,
            feedback_id=feedback_id,
            event_id=uuid4(),
            corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE.value,
            analyst_trust_level=AnalystTrustLevel.LEAD_SOC_ADMIN.value,
            analyst_id="admin_1",
            entity_key=entity,
        )
    )

    admin_token = create_jwt_token({
        "sub": "admin_user",
        "tenant_id": str(tenant_id),
        "role": "ADMIN",
    })

    response = client.post(
        f"/api/v1/feedback/convergence/{feedback_id}/rollback",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["feedback_id"] == str(feedback_id)
    assert data["restored_score"] == 0.50
    assert data["rolled_back_by"] == "admin_user"


def test_api_rollback_endpoint_analyst_forbidden() -> None:
    engine = TenantMemoryConvergenceEngine()
    set_convergence_engine(engine)
    client = TestClient(app)

    tenant_id = uuid4()
    feedback_id = uuid4()

    analyst_token = create_jwt_token({
        "sub": "analyst_user",
        "tenant_id": str(tenant_id),
        "role": "ANALYST",
    })

    response = client.post(
        f"/api/v1/feedback/convergence/{feedback_id}/rollback",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
