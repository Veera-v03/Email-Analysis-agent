"""Targeted unit and integration tests for Module 24 Phase 2 (AnalystFeedbackService & FastAPI Router)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.api.main import app
from src.common.constants import ActionTaken, Verdict
from src.events.feedback_events import AnalystVerdictSubmittedEvent
from src.feedback.models import (
    AnalystFeedbackRecordDTO,
    AnalystFeedbackSubmissionDTO,
    AnalystTrustLevel,
    AnalystVerdictCorrection,
    AuthenticatedAnalystDTO,
    FeedbackReasonCategory,
)
from src.feedback.router import (
    get_feedback_service,
    set_feedback_service,
)
from src.feedback.service import (
    AnalystFeedbackService,
    FeedbackDuplicateError,
    IncidentNotFoundError,
    InMemoryFeedbackStorage,
    InMemoryIncidentProvider,
)
from src.security.auth import create_jwt_token


class MockIncident:
    """Mock incident database entity for testing."""

    def __init__(
        self,
        incident_id: UUID,
        tenant_id: UUID,
        message_id: str = "msg_test_001",
        risk_score: int = 80,
        calibrated_probability: float | None = 0.88,
        verdict: str = "MALICIOUS",
        action_taken: str = "QUARANTINED",
    ) -> None:
        self.id = incident_id
        self.tenant_id = tenant_id
        self.message_id = message_id
        self.risk_score = risk_score
        self.calibrated_probability = calibrated_probability
        self.verdict = verdict
        self.action_taken = action_taken


# ===========================================================================
# 1. AnalystFeedbackService Unit Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_service_successful_analyst_submission() -> None:
    t_id = uuid4()
    inc_id = uuid4()
    mock_inc = MockIncident(incident_id=inc_id, tenant_id=t_id, risk_score=85, verdict="MALICIOUS")

    storage = InMemoryFeedbackStorage()
    inc_provider = InMemoryIncidentProvider([mock_inc])
    mock_publisher = AsyncMock()

    service = AnalystFeedbackService(
        storage=storage,
        incident_provider=inc_provider,
        event_publisher=mock_publisher,
    )

    caller = AuthenticatedAnalystDTO(
        analyst_id="analyst_alice",
        tenant_id=t_id,
        role="ANALYST",
        email="alice@sec.corp",
    )

    submission = AnalystFeedbackSubmissionDTO(
        incident_id=inc_id,
        message_id="msg_test_001",
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
        reason_category=FeedbackReasonCategory.AUTHORIZED_EXTERNAL_VENDOR,
        analyst_notes="Legitimate vendor",
        override_remediation=True,
    )

    record = await service.submit_feedback(inc_id, submission, caller)

    assert record.tenant_id == t_id
    assert record.incident_id == inc_id
    assert record.original_risk_score == 85
    assert record.original_verdict == Verdict.MALICIOUS
    assert record.corrected_verdict == AnalystVerdictCorrection.FALSE_POSITIVE
    assert record.analyst_id == "analyst_alice"
    assert record.analyst_trust_level == AnalystTrustLevel.JUNIOR_ANALYST
    assert record.convergence_weight == 0.50

    # Verify event published
    mock_publisher.publish.assert_awaited_once()
    event = mock_publisher.publish.call_args[0][0]
    assert isinstance(event, AnalystVerdictSubmittedEvent)
    assert event.feedback_id == record.feedback_id
    assert event.tenant_id == t_id
    assert event.analyst_id == "analyst_alice"


@pytest.mark.asyncio
async def test_service_successful_admin_submission_lead_trust() -> None:
    t_id = uuid4()
    inc_id = uuid4()
    mock_inc = MockIncident(incident_id=inc_id, tenant_id=t_id)

    storage = InMemoryFeedbackStorage()
    inc_provider = InMemoryIncidentProvider([mock_inc])
    service = AnalystFeedbackService(storage=storage, incident_provider=inc_provider)

    admin_caller = AuthenticatedAnalystDTO(
        analyst_id="admin_bob",
        tenant_id=t_id,
        role="ADMIN",
        email="admin@sec.corp",
    )

    submission = AnalystFeedbackSubmissionDTO(
        incident_id=inc_id,
        message_id="msg_test_001",
        corrected_verdict=AnalystVerdictCorrection.CONFIRMED_MALICIOUS,
        reason_category=FeedbackReasonCategory.OBFUSCATED_MALICIOUS_LINK,
    )

    record = await service.submit_feedback(inc_id, submission, admin_caller)
    assert record.analyst_trust_level == AnalystTrustLevel.LEAD_SOC_ADMIN
    assert record.convergence_weight == 1.00


@pytest.mark.asyncio
async def test_service_cross_tenant_incident_rejection() -> None:
    tenant_a = uuid4()
    tenant_b = uuid4()
    inc_id = uuid4()
    mock_inc = MockIncident(incident_id=inc_id, tenant_id=tenant_b)

    service = AnalystFeedbackService(
        storage=InMemoryFeedbackStorage(),
        incident_provider=InMemoryIncidentProvider([mock_inc]),
    )

    caller_a = AuthenticatedAnalystDTO(
        analyst_id="analyst_alice",
        tenant_id=tenant_a,
        role="ANALYST",
    )

    submission = AnalystFeedbackSubmissionDTO(
        incident_id=inc_id,
        message_id="msg_test_001",
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
        reason_category=FeedbackReasonCategory.OTHER,
    )

    with pytest.raises(IncidentNotFoundError):
        await service.submit_feedback(inc_id, submission, caller_a)


@pytest.mark.asyncio
async def test_service_incident_not_found() -> None:
    t_id = uuid4()
    service = AnalystFeedbackService(
        storage=InMemoryFeedbackStorage(),
        incident_provider=InMemoryIncidentProvider([]),
    )
    caller = AuthenticatedAnalystDTO(analyst_id="analyst_1", tenant_id=t_id, role="ANALYST")
    submission = AnalystFeedbackSubmissionDTO(
        incident_id=uuid4(),
        message_id="msg_test_001",
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
        reason_category=FeedbackReasonCategory.OTHER,
    )
    with pytest.raises(IncidentNotFoundError):
        await service.submit_feedback(submission.incident_id, submission, caller)


@pytest.mark.asyncio
async def test_service_same_analyst_5min_idempotency() -> None:
    t_id = uuid4()
    inc_id = uuid4()
    mock_inc = MockIncident(incident_id=inc_id, tenant_id=t_id)

    storage = InMemoryFeedbackStorage()
    service = AnalystFeedbackService(
        storage=storage,
        incident_provider=InMemoryIncidentProvider([mock_inc]),
    )

    caller = AuthenticatedAnalystDTO(analyst_id="analyst_1", tenant_id=t_id, role="ANALYST")
    submission = AnalystFeedbackSubmissionDTO(
        incident_id=inc_id,
        message_id="msg_test_001",
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
        reason_category=FeedbackReasonCategory.OTHER,
    )

    # First submission succeeds
    rec1 = await service.submit_feedback(inc_id, submission, caller)
    assert rec1 is not None

    # Immediate second submission raises FeedbackDuplicateError
    with pytest.raises(FeedbackDuplicateError) as exc_info:
        await service.submit_feedback(inc_id, submission, caller)

    assert exc_info.value.existing_feedback_id == rec1.feedback_id


@pytest.mark.asyncio
async def test_service_different_analysts_same_incident_both_accepted() -> None:
    t_id = uuid4()
    inc_id = uuid4()
    mock_inc = MockIncident(incident_id=inc_id, tenant_id=t_id)

    storage = InMemoryFeedbackStorage()
    service = AnalystFeedbackService(
        storage=storage,
        incident_provider=InMemoryIncidentProvider([mock_inc]),
    )

    caller1 = AuthenticatedAnalystDTO(analyst_id="analyst_1", tenant_id=t_id, role="ANALYST")
    caller2 = AuthenticatedAnalystDTO(analyst_id="analyst_2", tenant_id=t_id, role="ANALYST")

    submission = AnalystFeedbackSubmissionDTO(
        incident_id=inc_id,
        message_id="msg_test_001",
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
        reason_category=FeedbackReasonCategory.OTHER,
    )

    rec1 = await service.submit_feedback(inc_id, submission, caller1)
    rec2 = await service.submit_feedback(inc_id, submission, caller2)

    assert rec1.feedback_id != rec2.feedback_id
    history = await service.get_feedback_history(inc_id, caller1)
    assert len(history) == 2


@pytest.mark.asyncio
async def test_service_event_bus_failure_does_not_corrupt_persistence() -> None:
    t_id = uuid4()
    inc_id = uuid4()
    mock_inc = MockIncident(incident_id=inc_id, tenant_id=t_id)

    storage = InMemoryFeedbackStorage()
    failing_publisher = AsyncMock()
    failing_publisher.publish.side_effect = RuntimeError("Network timeout to event broker")

    service = AnalystFeedbackService(
        storage=storage,
        incident_provider=InMemoryIncidentProvider([mock_inc]),
        event_publisher=failing_publisher,
    )

    caller = AuthenticatedAnalystDTO(analyst_id="analyst_1", tenant_id=t_id, role="ANALYST")
    submission = AnalystFeedbackSubmissionDTO(
        incident_id=inc_id,
        message_id="msg_test_001",
        corrected_verdict=AnalystVerdictCorrection.FALSE_POSITIVE,
        reason_category=FeedbackReasonCategory.OTHER,
    )

    # Should persist successfully despite EventBus error
    record = await service.submit_feedback(inc_id, submission, caller)
    assert record.feedback_id is not None
    history = await storage.get_records_for_incident(t_id, inc_id)
    assert len(history) == 1


# ===========================================================================
# 2. FastAPI Endpoint Integration Tests
# ===========================================================================
@pytest.fixture
def client_and_service() -> tuple[TestClient, AnalystFeedbackService, InMemoryIncidentProvider]:
    storage = InMemoryFeedbackStorage()
    inc_provider = InMemoryIncidentProvider()
    publisher = AsyncMock()
    service = AnalystFeedbackService(
        storage=storage,
        incident_provider=inc_provider,
        event_publisher=publisher,
    )
    set_feedback_service(service)
    client = TestClient(app)
    return client, service, inc_provider


def test_api_submit_feedback_success(
    client_and_service: tuple[TestClient, AnalystFeedbackService, InMemoryIncidentProvider]
) -> None:
    client, service, inc_provider = client_and_service
    tenant_id = uuid4()
    incident_id = uuid4()

    inc_provider.register_incident(
        MockIncident(incident_id=incident_id, tenant_id=tenant_id, risk_score=90)
    )

    token = create_jwt_token({
        "sub": "alice_analyst",
        "tenant_id": str(tenant_id),
        "role": "ANALYST",
        "email": "alice@corp.com",
    })

    payload = {
        "incident_id": str(incident_id),
        "message_id": "msg_001",
        "corrected_verdict": "FALSE_POSITIVE",
        "reason_category": "AUTHORIZED_EXTERNAL_VENDOR",
        "analyst_notes": "Vendor newsletter approved by comms",
        "override_remediation": True,
        "evidence_tags": ["dmarc_result"],
    }

    response = client.post(
        f"/api/v1/feedback/incidents/{incident_id}",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == status.HTTP_202_ACCEPTED
    data = response.json()
    assert data["status"] == "ACCEPTED"
    assert data["incident_id"] == str(incident_id)
    assert "feedback_id" in data


def test_api_submit_feedback_unauthenticated_rejection(
    client_and_service: tuple[TestClient, AnalystFeedbackService, InMemoryIncidentProvider]
) -> None:
    client, _, _ = client_and_service
    incident_id = uuid4()
    response = client.post(
        f"/api/v1/feedback/incidents/{incident_id}",
        json={"incident_id": str(incident_id), "message_id": "m1", "corrected_verdict": "FALSE_POSITIVE", "reason_category": "OTHER"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_api_submit_feedback_auditor_read_only_rejection(
    client_and_service: tuple[TestClient, AnalystFeedbackService, InMemoryIncidentProvider]
) -> None:
    client, _, inc_provider = client_and_service
    tenant_id = uuid4()
    incident_id = uuid4()
    inc_provider.register_incident(MockIncident(incident_id=incident_id, tenant_id=tenant_id))

    token = create_jwt_token({
        "sub": "auditor_user",
        "tenant_id": str(tenant_id),
        "role": "AUDITOR",
    })

    payload = {
        "incident_id": str(incident_id),
        "message_id": "msg_001",
        "corrected_verdict": "FALSE_POSITIVE",
        "reason_category": "OTHER",
    }

    response = client.post(
        f"/api/v1/feedback/incidents/{incident_id}",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_api_submit_feedback_cross_tenant_rejection(
    client_and_service: tuple[TestClient, AnalystFeedbackService, InMemoryIncidentProvider]
) -> None:
    client, _, inc_provider = client_and_service
    tenant_a = uuid4()
    tenant_b = uuid4()
    incident_id = uuid4()

    # Incident belongs to tenant B
    inc_provider.register_incident(MockIncident(incident_id=incident_id, tenant_id=tenant_b))

    # Token belongs to tenant A
    token_a = create_jwt_token({
        "sub": "analyst_a",
        "tenant_id": str(tenant_a),
        "role": "ANALYST",
    })

    payload = {
        "incident_id": str(incident_id),
        "message_id": "msg_001",
        "corrected_verdict": "FALSE_POSITIVE",
        "reason_category": "OTHER",
    }

    response = client.post(
        f"/api/v1/feedback/incidents/{incident_id}",
        json=payload,
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_api_submit_feedback_5min_idempotency_conflict(
    client_and_service: tuple[TestClient, AnalystFeedbackService, InMemoryIncidentProvider]
) -> None:
    client, _, inc_provider = client_and_service
    tenant_id = uuid4()
    incident_id = uuid4()
    inc_provider.register_incident(MockIncident(incident_id=incident_id, tenant_id=tenant_id))

    token = create_jwt_token({
        "sub": "analyst_alice",
        "tenant_id": str(tenant_id),
        "role": "ANALYST",
    })

    payload = {
        "incident_id": str(incident_id),
        "message_id": "msg_001",
        "corrected_verdict": "FALSE_POSITIVE",
        "reason_category": "AUTHORIZED_EXTERNAL_VENDOR",
    }

    # 1. First submission succeeds
    resp1 = client.post(
        f"/api/v1/feedback/incidents/{incident_id}",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp1.status_code == status.HTTP_202_ACCEPTED
    first_fb_id = resp1.json()["feedback_id"]

    # 2. Second duplicate submission returns 409 Conflict
    resp2 = client.post(
        f"/api/v1/feedback/incidents/{incident_id}",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp2.status_code == status.HTTP_409_CONFLICT
    assert resp2.json()["detail"]["existing_feedback_id"] == first_fb_id


def test_api_get_feedback_history(
    client_and_service: tuple[TestClient, AnalystFeedbackService, InMemoryIncidentProvider]
) -> None:
    client, service, inc_provider = client_and_service
    tenant_id = uuid4()
    incident_id = uuid4()
    inc_provider.register_incident(MockIncident(incident_id=incident_id, tenant_id=tenant_id))

    token = create_jwt_token({
        "sub": "analyst_alice",
        "tenant_id": str(tenant_id),
        "role": "ANALYST",
    })

    # Initially empty history
    resp_empty = client.get(
        f"/api/v1/feedback/incidents/{incident_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp_empty.status_code == status.HTTP_200_OK
    assert resp_empty.json() == []

    # Submit feedback
    payload = {
        "incident_id": str(incident_id),
        "message_id": "msg_001",
        "corrected_verdict": "FALSE_POSITIVE",
        "reason_category": "AUTHORIZED_EXTERNAL_VENDOR",
    }
    client.post(
        f"/api/v1/feedback/incidents/{incident_id}",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )

    # Fetch history again
    resp_history = client.get(
        f"/api/v1/feedback/incidents/{incident_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp_history.status_code == status.HTTP_200_OK
    records = resp_history.json()
    assert len(records) == 1
    assert records[0]["corrected_verdict"] == "FALSE_POSITIVE"
    assert records[0]["tenant_id"] == str(tenant_id)
