"""Tenant memory convergence engine executing bounded Bayesian-style trust updates from analyst feedback."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from src.events.feedback_events import AnalystVerdictSubmittedEvent
from src.feedback.models import (
    ANALYST_TRUST_WEIGHTS,
    AnalystTrustLevel,
    AnalystVerdictCorrection,
    AuthenticatedAnalystDTO,
    ConvergenceResultDTO,
    ConvergenceRollbackResultDTO,
)
from src.utils.logging import get_logger

logger = get_logger("scamon.feedback.convergence")

# ===========================================================================
# Mathematical Constants & Signal Mapping
# ===========================================================================
MAX_CONVERGENCE_DELTA: float = 0.20
BASE_LEARNING_RATE: float = 0.20

FEEDBACK_SIGNAL_MAPPING: dict[str, float] = {
    AnalystVerdictCorrection.FALSE_POSITIVE.value: 1.0,
    AnalystVerdictCorrection.CONFIRMED_CLEAN.value: 0.80,
    AnalystVerdictCorrection.BENIGN_ANOMALY.value: 0.40,
    AnalystVerdictCorrection.NEEDS_ESCALATION.value: 0.0,
    AnalystVerdictCorrection.CONFIRMED_SUSPICIOUS.value: -0.50,
    AnalystVerdictCorrection.FALSE_NEGATIVE.value: -1.0,
    AnalystVerdictCorrection.CONFIRMED_MALICIOUS.value: -1.0,
}


# ===========================================================================
# Custom Exceptions
# ===========================================================================
class ConvergenceError(Exception):
    """Base exception for Module 24 convergence errors."""


class ConvergenceRecordNotFoundError(ConvergenceError):
    """Raised when a target convergence audit record is not found for rollback."""


class ConvergenceRollbackError(ConvergenceError):
    """Raised when a rollback operation is invalid or has already been performed."""


class ConvergenceUnauthorizedError(ConvergenceError):
    """Raised when caller lacks admin privileges to execute rollback."""


# ===========================================================================
# Convergence Memory & Audit Models
# ===========================================================================
class TenantEntityTrustRecord:
    """Internal mutable state representing a converged sender/domain trust node."""

    def __init__(
        self,
        entity_key: str,
        trust_score: float = 0.50,
        confidence_score: float = 0.50,
    ) -> None:
        self.entity_key = entity_key
        self.trust_score = trust_score
        self.confidence_score = confidence_score
        self.incident_count: int = 0
        self.false_positive_count: int = 0
        self.false_negative_count: int = 0
        self.last_updated: datetime = datetime.now(UTC)
        self.last_verdict: str = "INITIAL"


class ConvergenceAuditItem:
    """Immutable record capturing before/after states of a convergence update."""

    def __init__(
        self,
        event_id: UUID,
        feedback_id: UUID,
        tenant_id: UUID,
        entity_key: str,
        prior_score: float,
        posterior_score: float,
        delta: float,
        analyst_id: str,
        analyst_trust_level: str,
        applied_at: datetime | None = None,
    ) -> None:
        self.event_id = event_id
        self.feedback_id = feedback_id
        self.tenant_id = tenant_id
        self.entity_key = entity_key
        self.prior_score = prior_score
        self.posterior_score = posterior_score
        self.delta = delta
        self.analyst_id = analyst_id
        self.analyst_trust_level = analyst_trust_level
        self.applied_at = applied_at or datetime.now(UTC)
        self.rolled_back: bool = False
        self.rolled_back_by: str | None = None
        self.rolled_back_at: datetime | None = None


# ===========================================================================
# Central TenantMemoryConvergenceEngine
# ===========================================================================
class TenantMemoryConvergenceEngine:
    """Asynchronous engine updating tenant-scoped memory nodes from verified analyst feedback."""

    def __init__(self) -> None:
        # Tenant partitioned memory: tenant_id -> {entity_key: TenantEntityTrustRecord}
        self._tenant_entities: dict[UUID, dict[str, TenantEntityTrustRecord]] = {}
        # Tenant partitioned audit trail: tenant_id -> list[ConvergenceAuditItem]
        self._tenant_audits: dict[UUID, list[ConvergenceAuditItem]] = {}
        # Idempotency set: tenant_id -> set[UUID]
        self._processed_events: dict[UUID, set[UUID]] = {}
        # Fine-grained per-tenant locks to avoid cross-tenant contention
        self._tenant_locks: dict[UUID, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

    async def _get_tenant_lock(self, tenant_id: UUID) -> asyncio.Lock:
        async with self._global_lock:
            if tenant_id not in self._tenant_locks:
                self._tenant_locks[tenant_id] = asyncio.Lock()
            return self._tenant_locks[tenant_id]

    async def handle_event(self, event: AnalystVerdictSubmittedEvent) -> ConvergenceResultDTO:
        """EventBus consumer handler for AnalystVerdictSubmittedEvent."""
        entity_key = event.message_id
        return await self.apply_convergence(
            tenant_id=event.tenant_id,
            feedback_id=event.feedback_id,
            event_id=event.event_id,
            corrected_verdict=event.corrected_verdict,
            analyst_trust_level=event.analyst_trust_level,
            analyst_id=event.analyst_id,
            entity_key=entity_key,
        )

    async def apply_convergence(
        self,
        tenant_id: UUID,
        feedback_id: UUID,
        event_id: UUID,
        corrected_verdict: str,
        analyst_trust_level: str,
        analyst_id: str,
        entity_key: str,
    ) -> ConvergenceResultDTO:
        """Execute deterministic Bayesian trust convergence for a tenant entity."""
        lock = await self._get_tenant_lock(tenant_id)
        async with lock:
            # 1. Tenant Partition Initialization
            if tenant_id not in self._tenant_entities:
                self._tenant_entities[tenant_id] = {}
                self._tenant_audits[tenant_id] = []
                self._processed_events[tenant_id] = set()

            # 2. Idempotency Check
            if event_id in self._processed_events[tenant_id] or feedback_id in self._processed_events[tenant_id]:
                logger.info(
                    "Idempotent duplicate convergence skipped for event %s (tenant %s)",
                    event_id,
                    tenant_id,
                )
                prior = self._tenant_entities[tenant_id].get(entity_key, TenantEntityTrustRecord(entity_key)).trust_score
                return ConvergenceResultDTO(
                    feedback_id=feedback_id,
                    tenant_id=tenant_id,
                    entity_key=entity_key,
                    prior_score=prior,
                    posterior_score=prior,
                    delta=0.0,
                    applied=False,
                    reason="IDEMPOTENT_DUPLICATE",
                )

            # 3. Retrieve Prior Belief
            entities = self._tenant_entities[tenant_id]
            if entity_key not in entities:
                entities[entity_key] = TenantEntityTrustRecord(entity_key=entity_key)
            record = entities[entity_key]

            prior_score = record.trust_score

            # 4. Resolve Analyst Trust Weight
            try:
                trust_enum = AnalystTrustLevel(analyst_trust_level)
                trust_weight = ANALYST_TRUST_WEIGHTS.get(trust_enum, 0.50)
            except Exception:
                trust_weight = 0.50

            # 5. Resolve Feedback Signal
            signal = FEEDBACK_SIGNAL_MAPPING.get(corrected_verdict, 0.0)

            # 6. Compute Strictly Bounded Delta: Delta in [-0.20, +0.20]
            raw_delta = BASE_LEARNING_RATE * trust_weight * signal
            delta = max(-MAX_CONVERGENCE_DELTA, min(MAX_CONVERGENCE_DELTA, raw_delta))

            # 7. Compute Posterior Trust Score in [0.0, 1.0]
            posterior_score = max(0.0, min(1.0, prior_score + delta))

            # 8. Update Memory Entity State
            record.trust_score = posterior_score
            record.confidence_score = max(0.0, min(1.0, record.confidence_score + 0.05 * trust_weight))
            record.incident_count += 1
            if corrected_verdict == AnalystVerdictCorrection.FALSE_POSITIVE.value:
                record.false_positive_count += 1
            elif corrected_verdict in (
                AnalystVerdictCorrection.FALSE_NEGATIVE.value,
                AnalystVerdictCorrection.CONFIRMED_MALICIOUS.value,
            ):
                record.false_negative_count += 1
            record.last_updated = datetime.now(UTC)
            record.last_verdict = corrected_verdict

            # 9. Append to Immutable Audit Trail
            audit_item = ConvergenceAuditItem(
                event_id=event_id,
                feedback_id=feedback_id,
                tenant_id=tenant_id,
                entity_key=entity_key,
                prior_score=prior_score,
                posterior_score=posterior_score,
                delta=delta,
                analyst_id=analyst_id,
                analyst_trust_level=analyst_trust_level,
            )
            self._tenant_audits[tenant_id].append(audit_item)
            self._processed_events[tenant_id].add(event_id)
            self._processed_events[tenant_id].add(feedback_id)

            logger.info(
                "Convergence applied: tenant=%s entity=%s prior=%.2f posterior=%.2f delta=%.2f",
                tenant_id,
                entity_key,
                prior_score,
                posterior_score,
                delta,
            )

            return ConvergenceResultDTO(
                feedback_id=feedback_id,
                tenant_id=tenant_id,
                entity_key=entity_key,
                prior_score=prior_score,
                posterior_score=posterior_score,
                delta=delta,
                applied=True,
                reason="CONVERGENCE_APPLIED",
            )

    async def rollback_convergence(
        self,
        tenant_id: UUID,
        feedback_id: UUID,
        admin_caller: AuthenticatedAnalystDTO,
    ) -> ConvergenceRollbackResultDTO:
        """Administratively roll back a previous convergence update."""
        # 1. Enforce Admin Authorization
        if admin_caller.role.upper() not in ("ADMIN", "SUPER_ADMIN", "LEAD_SOC_ADMIN"):
            raise ConvergenceUnauthorizedError("Only administrative roles can roll back convergence updates")

        # 2. Enforce Tenant Boundary
        if admin_caller.tenant_id != tenant_id:
            raise ConvergenceUnauthorizedError("Caller cannot perform rollback outside their tenant boundary")

        lock = await self._get_tenant_lock(tenant_id)
        async with lock:
            audits = self._tenant_audits.get(tenant_id, [])
            target_audit: ConvergenceAuditItem | None = None
            for item in reversed(audits):
                if item.feedback_id == feedback_id:
                    target_audit = item
                    break

            if target_audit is None:
                raise ConvergenceRecordNotFoundError(
                    f"No convergence record found for feedback {feedback_id} in tenant {tenant_id}"
                )

            if target_audit.rolled_back:
                raise ConvergenceRollbackError(
                    f"Convergence update for feedback {feedback_id} has already been rolled back"
                )

            # 3. Restore Prior Score to Target Entity
            entities = self._tenant_entities.get(tenant_id, {})
            if target_audit.entity_key in entities:
                entity_record = entities[target_audit.entity_key]
                entity_record.trust_score = target_audit.prior_score
                entity_record.last_updated = datetime.now(UTC)

            target_audit.rolled_back = True
            target_audit.rolled_back_by = admin_caller.analyst_id
            target_audit.rolled_back_at = datetime.now(UTC)

            logger.info(
                "Rolled back convergence for feedback %s: entity %s restored to prior score %.2f by admin %s",
                feedback_id,
                target_audit.entity_key,
                target_audit.prior_score,
                admin_caller.analyst_id,
            )

            return ConvergenceRollbackResultDTO(
                feedback_id=feedback_id,
                tenant_id=tenant_id,
                entity_key=target_audit.entity_key,
                restored_score=target_audit.prior_score,
                rolled_back_by=admin_caller.analyst_id,
                message=f"Convergence update for feedback {feedback_id} successfully rolled back",
            )

    async def get_tenant_entity_trust(self, tenant_id: UUID, entity_key: str) -> float:
        """Fetch current converged reputation/trust score for an entity within tenant boundary."""
        lock = await self._get_tenant_lock(tenant_id)
        async with lock:
            entities = self._tenant_entities.get(tenant_id, {})
            if entity_key in entities:
                return entities[entity_key].trust_score
            return 0.50

    async def get_convergence_audit_trail(self, tenant_id: UUID) -> list[dict[str, Any]]:
        """Retrieve audit history of all convergence events for a tenant."""
        lock = await self._get_tenant_lock(tenant_id)
        async with lock:
            audits = self._tenant_audits.get(tenant_id, [])
            return [
                {
                    "event_id": str(item.event_id),
                    "feedback_id": str(item.feedback_id),
                    "tenant_id": str(item.tenant_id),
                    "entity_key": item.entity_key,
                    "prior_score": item.prior_score,
                    "posterior_score": item.posterior_score,
                    "delta": item.delta,
                    "analyst_id": item.analyst_id,
                    "analyst_trust_level": item.analyst_trust_level,
                    "applied_at": item.applied_at.isoformat(),
                    "rolled_back": item.rolled_back,
                    "rolled_back_by": item.rolled_back_by,
                    "rolled_back_at": item.rolled_back_at.isoformat() if item.rolled_back_at else None,
                }
                for item in audits
            ]
