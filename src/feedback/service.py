"""Analyst feedback processing service enforcing tenant isolation, idempotency, and audit trails."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable
from uuid import UUID, uuid4

from src.common.constants import ActionTaken, Verdict
from src.events.feedback_events import AnalystVerdictSubmittedEvent
from src.feedback.models import (
    ANALYST_TRUST_WEIGHTS,
    AnalystFeedbackRecordDTO,
    AnalystFeedbackSubmissionDTO,
    AnalystTrustLevel,
    AuthenticatedAnalystDTO,
)
from src.interfaces.event_publisher import IEventPublisher
from src.risk.calibrator import RiskScoreCalibrator
from src.utils.logging import get_logger

logger = get_logger("scamon.feedback.service")


# ===========================================================================
# Custom Exceptions
# ===========================================================================
class FeedbackServiceError(Exception):
    """Base exception for Module 24 Feedback Service errors."""


class IncidentNotFoundError(FeedbackServiceError):
    """Raised when an incident is not found or is inaccessible within the tenant boundary."""


class FeedbackDuplicateError(FeedbackServiceError):
    """Raised when a duplicate feedback submission is attempted within the 5-minute idempotency window."""

    def __init__(self, existing_feedback_id: UUID, message: str = "Duplicate feedback submission"):
        super().__init__(message)
        self.existing_feedback_id = existing_feedback_id


class UnauthorizedFeedbackError(FeedbackServiceError):
    """Raised when a caller lacks required permissions for the feedback operation."""


# ===========================================================================
# Storage & Incident Provider Protocols
# ===========================================================================
@runtime_checkable
class IFeedbackStorage(Protocol):
    """Protocol for persisting and retrieving immutable feedback audit records."""

    async def save_record(self, record: AnalystFeedbackRecordDTO) -> None:
        """Persist a newly created immutable feedback record."""
        ...

    async def get_records_for_incident(
        self, tenant_id: UUID, incident_id: UUID
    ) -> list[AnalystFeedbackRecordDTO]:
        """Retrieve all feedback audit records for a given incident."""
        ...

    async def get_recent_analyst_feedback(
        self,
        tenant_id: UUID,
        analyst_id: str,
        incident_id: UUID,
        window_seconds: int = 300,
    ) -> AnalystFeedbackRecordDTO | None:
        """Find recent feedback from the same analyst on the same incident within the time window."""
        ...


@runtime_checkable
class IIncidentProvider(Protocol):
    """Protocol for querying master security incident records."""

    async def get_incident(self, incident_id: UUID) -> Any | None:
        """Fetch incident by primary key UUID."""
        ...


# ===========================================================================
# In-Memory Reference Implementations
# ===========================================================================
class InMemoryFeedbackStorage(IFeedbackStorage):
    """Thread-safe, tenant-isolated in-memory storage for feedback audit records."""

    def __init__(self) -> None:
        self._records: list[AnalystFeedbackRecordDTO] = []
        self._lock = asyncio.Lock()

    async def save_record(self, record: AnalystFeedbackRecordDTO) -> None:
        async with self._lock:
            self._records.append(record)
            logger.info(
                "Persisted feedback record: id=%s tenant_id=%s incident_id=%s",
                record.feedback_id,
                record.tenant_id,
                record.incident_id,
            )

    async def get_records_for_incident(
        self, tenant_id: UUID, incident_id: UUID
    ) -> list[AnalystFeedbackRecordDTO]:
        async with self._lock:
            return [
                r
                for r in self._records
                if r.tenant_id == tenant_id and r.incident_id == incident_id
            ]

    async def get_recent_analyst_feedback(
        self,
        tenant_id: UUID,
        analyst_id: str,
        incident_id: UUID,
        window_seconds: int = 300,
    ) -> AnalystFeedbackRecordDTO | None:
        async with self._lock:
            cutoff = datetime.now(UTC) - timedelta(seconds=window_seconds)
            for r in reversed(self._records):
                if (
                    r.tenant_id == tenant_id
                    and r.analyst_id == analyst_id
                    and r.incident_id == incident_id
                    and r.created_at >= cutoff
                ):
                    return r
            return None


class InMemoryIncidentProvider(IIncidentProvider):
    """Simple in-memory incident provider for unit and integration testing."""

    def __init__(self, initial_incidents: list[Any] | None = None) -> None:
        self._incidents: dict[UUID, Any] = {
            getattr(inc, "id", getattr(inc, "incident_id", None)): inc
            for inc in (initial_incidents or [])
        }

    def register_incident(self, incident: Any) -> None:
        inc_id = getattr(incident, "id", getattr(incident, "incident_id", None))
        if inc_id:
            self._incidents[inc_id] = incident

    async def get_incident(self, incident_id: UUID) -> Any | None:
        return self._incidents.get(incident_id)


# ===========================================================================
# Central AnalystFeedbackService
# ===========================================================================
class AnalystFeedbackService:
    """Core domain service coordinating analyst feedback validation, persistence, and event emission."""

    def __init__(
        self,
        storage: IFeedbackStorage | None = None,
        incident_provider: IIncidentProvider | None = None,
        event_publisher: IEventPublisher | None = None,
        calibrator: RiskScoreCalibrator | None = None,
    ) -> None:
        self.storage = storage or InMemoryFeedbackStorage()
        self.incident_provider = incident_provider or InMemoryIncidentProvider()
        self.event_publisher = event_publisher
        self.calibrator = calibrator or RiskScoreCalibrator()

    async def submit_feedback(
        self,
        incident_id: UUID,
        submission: AnalystFeedbackSubmissionDTO,
        caller: AuthenticatedAnalystDTO,
    ) -> AnalystFeedbackRecordDTO:
        """Process and record an authenticated SOC analyst verdict correction.

        Enforces:
        - Incident existence and tenant boundary isolation.
        - 5-minute analyst idempotency (returns existing feedback conflict).
        - Trust level resolution and convergence weighting.
        - Immutable audit record persistence.
        - Asynchronous EventBus notification.
        """
        # 1. Validate Incident Existence & Tenant Boundary Isolation
        incident = await self.incident_provider.get_incident(incident_id)
        if incident is None:
            logger.warning("Feedback submission rejected: incident %s not found", incident_id)
            raise IncidentNotFoundError(f"Incident {incident_id} not found or inaccessible")

        incident_tenant_id = getattr(incident, "tenant_id", None)
        if incident_tenant_id != caller.tenant_id:
            logger.warning(
                "Tenant boundary mismatch: caller tenant %s tried to access incident %s (tenant %s)",
                caller.tenant_id,
                incident_id,
                incident_tenant_id,
            )
            raise IncidentNotFoundError(f"Incident {incident_id} not found or inaccessible")

        # 2. Enforce 5-Minute Analyst Idempotency Window
        recent_feedback = await self.storage.get_recent_analyst_feedback(
            tenant_id=caller.tenant_id,
            analyst_id=caller.analyst_id,
            incident_id=incident_id,
            window_seconds=300,
        )
        if recent_feedback is not None:
            logger.info(
                "Duplicate feedback within 5m window for analyst %s on incident %s (existing: %s)",
                caller.analyst_id,
                incident_id,
                recent_feedback.feedback_id,
            )
            raise FeedbackDuplicateError(
                existing_feedback_id=recent_feedback.feedback_id,
                message=f"Duplicate feedback submission within 5-minute window for incident {incident_id}",
            )

        # 3. Resolve Analyst Trust Level & Convergence Weight
        analyst_trust = caller.trust_level
        if analyst_trust is None:
            role_upper = caller.role.upper()
            if role_upper in ("ADMIN", "SUPER_ADMIN", "LEAD_SOC_ADMIN"):
                analyst_trust = AnalystTrustLevel.LEAD_SOC_ADMIN
            elif "SENIOR" in caller.analyst_id.upper() or "SENIOR" in caller.email.upper():
                analyst_trust = AnalystTrustLevel.SENIOR_ANALYST
            else:
                analyst_trust = AnalystTrustLevel.JUNIOR_ANALYST

        conv_weight = ANALYST_TRUST_WEIGHTS[analyst_trust]

        # 4. Extract Original Incident Decisioning Attributes
        orig_score = int(getattr(incident, "risk_score", 0))
        orig_score = max(0, min(100, orig_score))

        orig_prob = getattr(incident, "calibrated_probability", None)
        if orig_prob is None:
            orig_prob = self.calibrator.calibrate(orig_score)
        else:
            orig_prob = max(0.0, min(1.0, float(orig_prob)))

        raw_verdict = getattr(incident, "verdict", "CLEAN")
        try:
            orig_verdict = Verdict(raw_verdict)
        except Exception:
            orig_verdict = Verdict.CLEAN

        raw_action = getattr(incident, "action_taken", "DELIVERED")
        try:
            orig_action = ActionTaken(raw_action)
        except Exception:
            orig_action = ActionTaken.DELIVERED

        acc_id = getattr(incident, "account_id", incident_id)
        if not isinstance(acc_id, UUID):
            acc_id = incident_id

        msg_id = getattr(incident, "message_id", submission.message_id)

        # 5. Construct Immutable AnalystFeedbackRecordDTO
        record = AnalystFeedbackRecordDTO(
            feedback_id=uuid4(),
            tenant_id=caller.tenant_id,
            account_id=acc_id,
            incident_id=incident_id,
            message_id=msg_id,
            original_risk_score=orig_score,
            original_calibrated_prob=orig_prob,
            original_verdict=orig_verdict,
            original_action=orig_action,
            corrected_verdict=submission.corrected_verdict,
            reason_category=submission.reason_category,
            analyst_id=caller.analyst_id,
            analyst_trust_level=analyst_trust,
            analyst_notes=submission.analyst_notes,
            convergence_applied=False,
            convergence_weight=conv_weight,
            created_at=datetime.now(UTC),
        )

        # 6. Persist Feedback Record to Audit Storage
        await self.storage.save_record(record)

        # 7. Publish Event to EventBus
        if self.event_publisher is not None:
            event = AnalystVerdictSubmittedEvent(
                tenant_id=record.tenant_id,
                feedback_id=record.feedback_id,
                incident_id=record.incident_id,
                message_id=record.message_id,
                original_verdict=record.original_verdict.value,
                corrected_verdict=record.corrected_verdict.value,
                reason_category=record.reason_category.value,
                analyst_id=record.analyst_id,
                analyst_trust_level=record.analyst_trust_level.value,
            )
            try:
                await self.event_publisher.publish(event)
                logger.info("Published AnalystVerdictSubmittedEvent for feedback %s", record.feedback_id)
            except Exception as bus_err:
                logger.error(
                    "EventBus publication failed for feedback %s: %s",
                    record.feedback_id,
                    bus_err,
                    exc_info=True,
                )

        return record

    async def get_feedback_history(
        self,
        incident_id: UUID,
        caller: AuthenticatedAnalystDTO,
    ) -> list[AnalystFeedbackRecordDTO]:
        """Retrieve feedback audit history for an incident enforcing tenant isolation."""
        incident = await self.incident_provider.get_incident(incident_id)
        if incident is not None:
            if getattr(incident, "tenant_id", None) != caller.tenant_id:
                raise IncidentNotFoundError(f"Incident {incident_id} not found or inaccessible")

        return await self.storage.get_records_for_incident(
            tenant_id=caller.tenant_id,
            incident_id=incident_id,
        )
