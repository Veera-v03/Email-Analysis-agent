"""Targeted unit and integration tests for Module 24 Phase 4 (AdaptiveSensitivityTuner & Recommendations API)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.api.main import app
from src.common.constants import ActionTaken, Verdict
from src.feedback.models import (
    AnalystFeedbackRecordDTO,
    AnalystTrustLevel,
    AnalystVerdictCorrection,
    AuthenticatedAnalystDTO,
    FeedbackReasonCategory,
    RecommendationDirection,
    RecommendationStatus,
)
from src.feedback.router import set_sensitivity_tuner
from src.feedback.service import InMemoryFeedbackStorage
from src.feedback.tuner import (
    AdaptiveSensitivityTuner,
    RecommendationAlreadyAppliedError,
    RecommendationNotFoundError,
    TunerUnauthorizedError,
    step_down_sensitivity,
    step_up_sensitivity,
)
from src.security.auth import create_jwt_token


def _create_mock_feedback_record(
    tenant_id: UUID,
    verdict_correction: AnalystVerdictCorrection,
    created_at: datetime | None = None,
) -> AnalystFeedbackRecordDTO:
    """Helper creating an immutable feedback record for testing analytics."""
    return AnalystFeedbackRecordDTO(
        feedback_id=uuid4(),
        tenant_id=tenant_id,
        account_id=uuid4(),
        incident_id=uuid4(),
        message_id="msg_test",
        original_risk_score=80,
        original_calibrated_prob=0.85,
        original_verdict=Verdict.MALICIOUS,
        original_action=ActionTaken.QUARANTINED,
        corrected_verdict=verdict_correction,
        reason_category=FeedbackReasonCategory.OTHER,
        analyst_id="analyst@sec.corp",
        analyst_trust_level=AnalystTrustLevel.SENIOR_ANALYST,
        created_at=created_at or datetime.now(UTC),
    )


# ===========================================================================
# 1. Sensitivity Stepping Unit Tests
# ===========================================================================
def test_sensitivity_stepping_logic() -> None:
    # Step down: AGGRESSIVE -> BALANCED -> PERMISSIVE -> PERMISSIVE
    assert step_down_sensitivity("AGGRESSIVE") == "BALANCED"
    assert step_down_sensitivity("BALANCED") == "PERMISSIVE"
    assert step_down_sensitivity("PERMISSIVE") == "PERMISSIVE"

    # Step up: PERMISSIVE -> BALANCED -> AGGRESSIVE -> AGGRESSIVE
    assert step_up_sensitivity("PERMISSIVE") == "BALANCED"
    assert step_up_sensitivity("BALANCED") == "AGGRESSIVE"
    assert step_up_sensitivity("AGGRESSIVE") == "AGGRESSIVE"


# ===========================================================================
# 2. Window Analytics & Error Rate Calculations
# ===========================================================================
@pytest.mark.asyncio
async def test_tuner_window_analytics_calculations() -> None:
    storage = InMemoryFeedbackStorage()
    tuner = AdaptiveSensitivityTuner(feedback_storage=storage, min_sample_size=5)
    tenant_id = uuid4()
    now = datetime.now(UTC)

    # Add 10 False Positives, 10 Confirmed Clean (inside 7-day window)
    for _ in range(10):
        await storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.FALSE_POSITIVE, now - timedelta(days=2))
        )
        await storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.CONFIRMED_CLEAN, now - timedelta(days=3))
        )

    # Add 5 False Negatives, 15 Confirmed Malicious (inside 30-day window, but outside 7-day)
    for _ in range(5):
        await storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.FALSE_NEGATIVE, now - timedelta(days=15))
        )
    for _ in range(15):
        await storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.CONFIRMED_MALICIOUS, now - timedelta(days=20))
        )

    # 7-day Analytics: 10 FP, 10 Clean -> 20 total. FPR = 10 / (10 + 10) = 0.50 (50%), FNR = None (0 denominator)
    a7 = await tuner.calculate_window_analytics(tenant_id, window_days=7, reference_time=now)
    assert a7.sample_count == 20
    assert a7.false_positive_count == 10
    assert a7.confirmed_clean_count == 10
    assert a7.false_positive_rate == 0.50
    assert a7.false_negative_rate is None

    # 30-day Analytics: 10 FP, 10 Clean, 5 FN, 15 Malicious -> 40 total
    # FPR = 10 / (10 + 10) = 0.50
    # FNR = 5 / (5 + 15) = 0.25
    a30 = await tuner.calculate_window_analytics(tenant_id, window_days=30, reference_time=now)
    assert a30.sample_count == 40
    assert a30.false_positive_rate == 0.50
    assert a30.false_negative_rate == 0.25
    assert a30.error_distribution["FALSE_POSITIVE"] == 10
    assert a30.error_distribution["FALSE_NEGATIVE"] == 5


@pytest.mark.asyncio
async def test_tuner_zero_denominator_safe() -> None:
    storage = InMemoryFeedbackStorage()
    tuner = AdaptiveSensitivityTuner(feedback_storage=storage, min_sample_size=5)
    tenant_id = uuid4()

    # Empty storage
    analytics = await tuner.calculate_window_analytics(tenant_id, window_days=30)
    assert analytics.sample_count == 0
    assert analytics.false_positive_rate is None
    assert analytics.false_negative_rate is None


# ===========================================================================
# 3. Recommendation Generation Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_recommendation_insufficient_data() -> None:
    storage = InMemoryFeedbackStorage()
    tuner = AdaptiveSensitivityTuner(feedback_storage=storage, min_sample_size=10)
    tenant_id = uuid4()
    now = datetime.now(UTC)

    # Only 3 samples (< 10)
    for _ in range(3):
        await storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.FALSE_POSITIVE, now)
        )

    rec = await tuner.generate_recommendation(tenant_id, window_days=30, current_sensitivity="BALANCED")
    assert rec.direction == RecommendationDirection.INSUFFICIENT_DATA
    assert rec.current_sensitivity == "BALANCED"
    assert rec.recommended_sensitivity == "BALANCED"
    assert "below the minimum statistical requirement" in rec.explanation


@pytest.mark.asyncio
async def test_recommendation_high_fpr_step_down() -> None:
    storage = InMemoryFeedbackStorage()
    tuner = AdaptiveSensitivityTuner(feedback_storage=storage, min_sample_size=10)
    tenant_id = uuid4()
    now = datetime.now(UTC)

    # 10 FP + 10 Clean (FPR = 50% >= 15%, FNR is None)
    for _ in range(10):
        await storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.FALSE_POSITIVE, now)
        )
        await storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.CONFIRMED_CLEAN, now)
        )

    rec = await tuner.generate_recommendation(tenant_id, window_days=30, current_sensitivity="AGGRESSIVE")
    assert rec.direction == RecommendationDirection.DECREASE_SENSITIVITY
    assert rec.current_sensitivity == "AGGRESSIVE"
    assert rec.recommended_sensitivity == "BALANCED"
    assert rec.status == RecommendationStatus.PENDING_REVIEW
    assert "False Positive Rate is 50.0%" in rec.explanation


@pytest.mark.asyncio
async def test_recommendation_high_fnr_step_up() -> None:
    storage = InMemoryFeedbackStorage()
    tuner = AdaptiveSensitivityTuner(feedback_storage=storage, min_sample_size=10)
    tenant_id = uuid4()
    now = datetime.now(UTC)

    # 4 FN + 16 Malicious (FNR = 20% >= 5%, FPR is None)
    for _ in range(4):
        await storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.FALSE_NEGATIVE, now)
        )
    for _ in range(16):
        await storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.CONFIRMED_MALICIOUS, now)
        )

    rec = await tuner.generate_recommendation(tenant_id, window_days=30, current_sensitivity="PERMISSIVE")
    assert rec.direction == RecommendationDirection.INCREASE_SENSITIVITY
    assert rec.current_sensitivity == "PERMISSIVE"
    assert rec.recommended_sensitivity == "BALANCED"
    assert "False Negative Rate is 20.0%" in rec.explanation


@pytest.mark.asyncio
async def test_recommendation_maintain() -> None:
    storage = InMemoryFeedbackStorage()
    tuner = AdaptiveSensitivityTuner(feedback_storage=storage, min_sample_size=10)
    tenant_id = uuid4()
    now = datetime.now(UTC)

    # 1 FP + 19 Clean (FPR = 5% < 15%), 0 FN + 10 Malicious (FNR = 0% < 5%)
    await storage.save_record(
        _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.FALSE_POSITIVE, now)
    )
    for _ in range(19):
        await storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.CONFIRMED_CLEAN, now)
        )
    for _ in range(10):
        await storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.CONFIRMED_MALICIOUS, now)
        )

    rec = await tuner.generate_recommendation(tenant_id, window_days=30, current_sensitivity="BALANCED")
    assert rec.direction == RecommendationDirection.MAINTAIN
    assert rec.recommended_sensitivity == "BALANCED"


# ===========================================================================
# 4. Recommendation Application & Audit Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_apply_recommendation_success_and_idempotency() -> None:
    storage = InMemoryFeedbackStorage()
    tuner = AdaptiveSensitivityTuner(feedback_storage=storage, min_sample_size=5)
    tenant_id = uuid4()
    now = datetime.now(UTC)

    for _ in range(10):
        await storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.FALSE_POSITIVE, now)
        )
        await storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.CONFIRMED_CLEAN, now)
        )

    tuner.set_tenant_sensitivity(tenant_id, "AGGRESSIVE")
    rec = await tuner.generate_recommendation(tenant_id, window_days=30)
    assert rec.recommended_sensitivity == "BALANCED"

    admin_caller = AuthenticatedAnalystDTO(
        analyst_id="admin_sarah",
        tenant_id=tenant_id,
        role="ADMIN",
    )

    # 1. Apply recommendation successfully
    apply_res = await tuner.apply_recommendation(tenant_id, rec.recommendation_id, admin_caller)
    assert apply_res.previous_sensitivity == "AGGRESSIVE"
    assert apply_res.new_sensitivity == "BALANCED"
    assert apply_res.applied_by == "admin_sarah"
    assert tuner.get_tenant_sensitivity(tenant_id) == "BALANCED"

    # Verify updated record status
    recs = await tuner.get_tenant_recommendations(tenant_id)
    assert recs[0].status == RecommendationStatus.APPLIED
    assert recs[0].applied_by == "admin_sarah"

    # 2. Attempting second application raises RecommendationAlreadyAppliedError (Idempotency)
    with pytest.raises(RecommendationAlreadyAppliedError):
        await tuner.apply_recommendation(tenant_id, rec.recommendation_id, admin_caller)


@pytest.mark.asyncio
async def test_apply_recommendation_unauthorized_role_rejected() -> None:
    tuner = AdaptiveSensitivityTuner()
    tenant_id = uuid4()
    rec_id = uuid4()

    junior_caller = AuthenticatedAnalystDTO(
        analyst_id="junior_alice",
        tenant_id=tenant_id,
        role="ANALYST",
    )

    with pytest.raises(TunerUnauthorizedError):
        await tuner.apply_recommendation(tenant_id, rec_id, junior_caller)


# ===========================================================================
# 5. FastAPI Endpoint Integration Tests
# ===========================================================================
def test_api_get_and_apply_recommendations() -> None:
    storage = InMemoryFeedbackStorage()
    tuner = AdaptiveSensitivityTuner(feedback_storage=storage, min_sample_size=5)
    set_sensitivity_tuner(tuner)
    client = TestClient(app)

    tenant_id = uuid4()
    now = datetime.now(UTC)

    for _ in range(10):
        asyncio.run(storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.FALSE_POSITIVE, now)
        ))
        asyncio.run(storage.save_record(
            _create_mock_feedback_record(tenant_id, AnalystVerdictCorrection.CONFIRMED_CLEAN, now)
        ))

    tuner.set_tenant_sensitivity(tenant_id, "AGGRESSIVE")
    rec = asyncio.run(tuner.generate_recommendation(tenant_id, window_days=30))

    admin_token = create_jwt_token({
        "sub": "lead_admin",
        "tenant_id": str(tenant_id),
        "role": "ADMIN",
    })

    # 1. GET /api/v1/feedback/recommendations
    get_resp = client.get(
        "/api/v1/feedback/recommendations",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert get_resp.status_code == status.HTTP_200_OK
    recs_data = get_resp.json()
    assert len(recs_data) == 1
    assert recs_data[0]["recommendation_id"] == str(rec.recommendation_id)
    assert recs_data[0]["recommended_sensitivity"] == "BALANCED"

    # 2. POST /api/v1/feedback/recommendations/{id}/apply
    apply_resp = client.post(
        f"/api/v1/feedback/recommendations/{rec.recommendation_id}/apply",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert apply_resp.status_code == status.HTTP_200_OK
    data = apply_resp.json()
    assert data["previous_sensitivity"] == "AGGRESSIVE"
    assert data["new_sensitivity"] == "BALANCED"
    assert data["applied_by"] == "lead_admin"


def test_api_apply_recommendation_analyst_forbidden() -> None:
    tuner = AdaptiveSensitivityTuner()
    set_sensitivity_tuner(tuner)
    client = TestClient(app)

    tenant_id = uuid4()
    rec_id = uuid4()

    analyst_token = create_jwt_token({
        "sub": "analyst_alice",
        "tenant_id": str(tenant_id),
        "role": "ANALYST",
    })

    apply_resp = client.post(
        f"/api/v1/feedback/recommendations/{rec_id}/apply",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert apply_resp.status_code == status.HTTP_403_FORBIDDEN
