"""FastAPI router for Module 24 Analyst Feedback endpoints."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from src.feedback.convergence import (
    ConvergenceRecordNotFoundError,
    ConvergenceRollbackError,
    ConvergenceUnauthorizedError,
    TenantMemoryConvergenceEngine,
)
from src.feedback.models import (
    AnalystFeedbackRecordDTO,
    AnalystFeedbackResponseDTO,
    AnalystFeedbackSubmissionDTO,
    ApplyRecommendationResponseDTO,
    AuthenticatedAnalystDTO,
    ConvergenceRollbackResultDTO,
    SensitivityRecommendationDTO,
)
from src.feedback.service import (
    AnalystFeedbackService,
    FeedbackDuplicateError,
    IncidentNotFoundError,
    UnauthorizedFeedbackError,
    to_canonical_uuid,
)
from src.feedback.tuner import (
    AdaptiveSensitivityTuner,
    RecommendationAlreadyAppliedError,
    RecommendationNotFoundError,
    TunerUnauthorizedError,
)
from src.security.auth import decode_jwt_token
from src.utils.logging import get_logger

logger = get_logger("scamon.feedback.router")

feedback_router = APIRouter(prefix="/api/v1/feedback", tags=["Feedback"])

_feedback_service_singleton: AnalystFeedbackService | None = None


def get_feedback_service() -> AnalystFeedbackService:
    """Dependency resolver for AnalystFeedbackService singleton."""
    global _feedback_service_singleton
    if _feedback_service_singleton is None:
        _feedback_service_singleton = AnalystFeedbackService()
    return _feedback_service_singleton


def set_feedback_service(service: AnalystFeedbackService | None) -> None:
    """Override feedback service singleton for testing / dependency injection."""
    global _feedback_service_singleton
    _feedback_service_singleton = service


async def get_current_analyst(
    authorization: str | None = Header(default=None, alias="Authorization"),
    token_param: str | None = Query(default=None, alias="token"),
) -> AuthenticatedAnalystDTO:
    """Resolve and validate authenticated analyst context from Bearer JWT token."""
    raw_token = None
    if authorization and authorization.startswith("Bearer "):
        raw_token = authorization.split("Bearer ")[1].strip()
    elif token_param:
        raw_token = token_param.strip()

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization Bearer header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims: dict[str, Any] = decode_jwt_token(raw_token)
    except Exception as exc:
        logger.warning("Token verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    raw_tenant = claims.get("tenant_id") or claims.get("org_id")
    if not raw_tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication token missing tenant identity claim",
        )

    try:
        tenant_id = to_canonical_uuid(raw_tenant)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Malformed tenant_id claim in authentication token",
        ) from err

    role = str(claims.get("role") or "ANALYST").upper()
    allowed_roles = {"ANALYST", "ADMIN", "SUPER_ADMIN", "LEAD_SOC_ADMIN", "AUDITOR"}
    if role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{role}' is not authorized for feedback operations",
        )

    analyst_id = str(claims.get("sub") or claims.get("user_id") or claims.get("email") or "analyst")
    email = str(claims.get("email") or "")

    return AuthenticatedAnalystDTO(
        analyst_id=analyst_id,
        tenant_id=tenant_id,
        role=role,
        email=email,
    )


@feedback_router.post(
    "/incidents/{incident_id}",
    response_model=AnalystFeedbackResponseDTO,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit analyst verdict correction",
    description="Submit human-in-the-loop analyst feedback on an analyzed incident with 5m idempotency.",
)
async def submit_incident_feedback(
    incident_id: UUID,
    submission: AnalystFeedbackSubmissionDTO,
    caller: AuthenticatedAnalystDTO = Depends(get_current_analyst),
    service: AnalystFeedbackService = Depends(get_feedback_service),
) -> AnalystFeedbackResponseDTO:
    """Submit and record verified analyst feedback for an incident."""
    if caller.role == "AUDITOR":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Auditor role is read-only and cannot submit feedback corrections",
        )

    try:
        record = await service.submit_feedback(
            incident_id=incident_id,
            submission=submission,
            caller=caller,
        )
        return AnalystFeedbackResponseDTO(
            status="ACCEPTED",
            feedback_id=record.feedback_id,
            incident_id=record.incident_id,
            message="Analyst feedback accepted and queued for convergence",
        )
    except IncidentNotFoundError as not_found_err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(not_found_err),
        ) from not_found_err
    except FeedbackDuplicateError as dup_err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": str(dup_err),
                "existing_feedback_id": str(dup_err.existing_feedback_id),
            },
        ) from dup_err
    except UnauthorizedFeedbackError as auth_err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(auth_err),
        ) from auth_err


@feedback_router.get(
    "/incidents/{incident_id}",
    response_model=list[AnalystFeedbackRecordDTO],
    status_code=status.HTTP_200_OK,
    summary="Retrieve incident feedback history",
    description="Retrieve all immutable audit feedback records associated with the incident.",
)
async def get_incident_feedback_history(
    incident_id: UUID,
    caller: AuthenticatedAnalystDTO = Depends(get_current_analyst),
    service: AnalystFeedbackService = Depends(get_feedback_service),
) -> list[AnalystFeedbackRecordDTO]:
    """Retrieve full audit trail of analyst feedback for the given incident."""
    try:
        return await service.get_feedback_history(
            incident_id=incident_id,
            caller=caller,
        )
    except IncidentNotFoundError as not_found_err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(not_found_err),
        ) from not_found_err


_convergence_engine_singleton: TenantMemoryConvergenceEngine | None = None


def get_convergence_engine() -> TenantMemoryConvergenceEngine:
    """Dependency resolver for TenantMemoryConvergenceEngine singleton."""
    global _convergence_engine_singleton
    if _convergence_engine_singleton is None:
        _convergence_engine_singleton = TenantMemoryConvergenceEngine()
    return _convergence_engine_singleton


def set_convergence_engine(engine: TenantMemoryConvergenceEngine | None) -> None:
    """Override convergence engine singleton for testing."""
    global _convergence_engine_singleton
    _convergence_engine_singleton = engine


@feedback_router.post(
    "/convergence/{feedback_id}/rollback",
    response_model=ConvergenceRollbackResultDTO,
    status_code=status.HTTP_200_OK,
    summary="Administratively rollback convergence update",
    description="Roll back a previous tenant memory convergence update. Requires ADMIN or SUPER_ADMIN role.",
)
async def rollback_incident_convergence(
    feedback_id: UUID,
    caller: AuthenticatedAnalystDTO = Depends(get_current_analyst),
    engine: TenantMemoryConvergenceEngine = Depends(get_convergence_engine),
) -> ConvergenceRollbackResultDTO:
    """Administratively roll back a previous memory convergence update."""
    if caller.role not in ("ADMIN", "SUPER_ADMIN", "LEAD_SOC_ADMIN"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrative roles can roll back convergence updates",
        )

    try:
        return await engine.rollback_convergence(
            tenant_id=caller.tenant_id,
            feedback_id=feedback_id,
            admin_caller=caller,
        )
    except ConvergenceRecordNotFoundError as not_found_err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(not_found_err),
        ) from not_found_err
    except ConvergenceRollbackError as rollback_err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(rollback_err),
        ) from rollback_err
    except ConvergenceUnauthorizedError as auth_err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(auth_err),
        ) from auth_err


_tuner_singleton: AdaptiveSensitivityTuner | None = None


def get_sensitivity_tuner() -> AdaptiveSensitivityTuner:
    """Dependency resolver for AdaptiveSensitivityTuner singleton."""
    global _tuner_singleton
    if _tuner_singleton is None:
        _tuner_singleton = AdaptiveSensitivityTuner()
    return _tuner_singleton


def set_sensitivity_tuner(tuner: AdaptiveSensitivityTuner | None) -> None:
    """Override sensitivity tuner singleton for testing."""
    global _tuner_singleton
    _tuner_singleton = tuner


@feedback_router.get(
    "/recommendations",
    response_model=list[SensitivityRecommendationDTO],
    status_code=status.HTTP_200_OK,
    summary="Retrieve tenant sensitivity recommendations",
    description="Retrieve all generated advisory risk sensitivity recommendations for the authenticated tenant.",
)
async def get_tenant_sensitivity_recommendations(
    caller: AuthenticatedAnalystDTO = Depends(get_current_analyst),
    tuner: AdaptiveSensitivityTuner = Depends(get_sensitivity_tuner),
) -> list[SensitivityRecommendationDTO]:
    """Retrieve all advisory sensitivity recommendations for caller's tenant."""
    return await tuner.get_tenant_recommendations(tenant_id=caller.tenant_id)


@feedback_router.post(
    "/recommendations/{recommendation_id}/apply",
    response_model=ApplyRecommendationResponseDTO,
    status_code=status.HTTP_200_OK,
    summary="Administratively apply sensitivity recommendation",
    description="Approve and apply an advisory sensitivity recommendation to tenant profile. Requires ADMIN or SUPER_ADMIN role.",
)
async def apply_sensitivity_recommendation_endpoint(
    recommendation_id: UUID,
    caller: AuthenticatedAnalystDTO = Depends(get_current_analyst),
    tuner: AdaptiveSensitivityTuner = Depends(get_sensitivity_tuner),
) -> ApplyRecommendationResponseDTO:
    """Administratively apply an advisory sensitivity recommendation."""
    if caller.role not in ("ADMIN", "SUPER_ADMIN", "LEAD_SOC_ADMIN"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrative roles can apply sensitivity recommendations",
        )

    try:
        return await tuner.apply_recommendation(
            tenant_id=caller.tenant_id,
            recommendation_id=recommendation_id,
            admin_caller=caller,
        )
    except RecommendationNotFoundError as not_found_err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(not_found_err),
        ) from not_found_err
    except RecommendationAlreadyAppliedError as applied_err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(applied_err),
        ) from applied_err
    except TunerUnauthorizedError as auth_err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(auth_err),
        ) from auth_err
