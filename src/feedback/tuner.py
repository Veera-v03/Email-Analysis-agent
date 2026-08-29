"""Adaptive sensitivity tuner analyzing historical analyst feedback to produce explainable, advisory policy recommendations."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from src.feedback.models import (
    AnalystFeedbackRecordDTO,
    AnalystVerdictCorrection,
    ApplyRecommendationResponseDTO,
    AuthenticatedAnalystDTO,
    RecommendationDirection,
    RecommendationStatus,
    RollingWindowAnalyticsDTO,
    SensitivityRecommendationDTO,
)
from src.feedback.service import IFeedbackStorage, InMemoryFeedbackStorage
from src.utils.logging import get_logger

logger = get_logger("scamon.feedback.tuner")

# ===========================================================================
# Configuration Constants
# ===========================================================================
DEFAULT_MIN_SAMPLE_SIZE: int = 10
HIGH_FPR_THRESHOLD: float = 0.15  # >= 15% false positives -> suggest decrease sensitivity
LOW_FNR_THRESHOLD: float = 0.05   # < 5% false negatives tolerance
HIGH_FNR_THRESHOLD: float = 0.05  # >= 5% false negatives -> suggest increase sensitivity
LOW_FPR_THRESHOLD: float = 0.10   # < 10% false positives tolerance


# ===========================================================================
# Custom Exceptions
# ===========================================================================
class TunerError(Exception):
    """Base exception for Module 24 Tuner errors."""


class RecommendationNotFoundError(TunerError):
    """Raised when a specified recommendation cannot be found."""


class RecommendationAlreadyAppliedError(TunerError):
    """Raised when an administrator attempts to re-apply an already applied recommendation."""


class TunerUnauthorizedError(TunerError):
    """Raised when caller lacks required admin privileges to apply a recommendation."""


# ===========================================================================
# Sensitivity Stepping Helpers
# ===========================================================================
def step_down_sensitivity(current: str) -> str:
    """Decrease sensitivity policy by one bounded tier."""
    cur_upper = current.upper()
    if cur_upper in ("AGGRESSIVE", "HIGH"):
        return "BALANCED"
    elif cur_upper in ("BALANCED", "STANDARD"):
        return "PERMISSIVE"
    return "PERMISSIVE"


def step_up_sensitivity(current: str) -> str:
    """Increase sensitivity policy by one bounded tier."""
    cur_upper = current.upper()
    if cur_upper in ("PERMISSIVE", "LOW"):
        return "BALANCED"
    elif cur_upper in ("BALANCED", "STANDARD"):
        return "AGGRESSIVE"
    return "AGGRESSIVE"


# ===========================================================================
# Central AdaptiveSensitivityTuner
# ===========================================================================
class AdaptiveSensitivityTuner:
    """Calculates rolling-window error rates and produces advisory sensitivity recommendations."""

    def __init__(
        self,
        feedback_storage: IFeedbackStorage | None = None,
        min_sample_size: int = DEFAULT_MIN_SAMPLE_SIZE,
    ) -> None:
        self.feedback_storage = feedback_storage or InMemoryFeedbackStorage()
        self.min_sample_size = min_sample_size
        # Tenant partitioned recommendations: tenant_id -> dict[recommendation_id, SensitivityRecommendationDTO]
        self._recommendations: dict[UUID, dict[UUID, SensitivityRecommendationDTO]] = {}
        # Tenant partitioned active sensitivity settings: tenant_id -> current_sensitivity_str
        self._tenant_active_sensitivity: dict[UUID, str] = {}
        self._locks: dict[UUID, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

    async def _get_tenant_lock(self, tenant_id: UUID) -> asyncio.Lock:
        async with self._global_lock:
            if tenant_id not in self._locks:
                self._locks[tenant_id] = asyncio.Lock()
            return self._locks[tenant_id]

    def set_tenant_sensitivity(self, tenant_id: UUID, sensitivity: str) -> None:
        """Seed or override the active sensitivity setting for a tenant."""
        self._tenant_active_sensitivity[tenant_id] = sensitivity.upper()

    def get_tenant_sensitivity(self, tenant_id: UUID) -> str:
        """Return the current active sensitivity setting for a tenant (default BALANCED)."""
        return self._tenant_active_sensitivity.get(tenant_id, "BALANCED")

    async def calculate_window_analytics(
        self,
        tenant_id: UUID,
        window_days: int = 30,
        reference_time: datetime | None = None,
    ) -> RollingWindowAnalyticsDTO:
        """Calculate FPR, FNR, and error distribution over a rolling timestamp window."""
        end_time = reference_time or datetime.now(UTC)
        start_time = end_time - timedelta(days=window_days)

        lock = await self._get_tenant_lock(tenant_id)
        async with lock:
            # Query all records for this tenant
            records: list[AnalystFeedbackRecordDTO] = []
            if hasattr(self.feedback_storage, "_records"):
                records = [
                    r for r in getattr(self.feedback_storage, "_records", [])
                    if r.tenant_id == tenant_id
                ]

            # Filter by window_start <= created_at <= window_end
            window_records = [
                r for r in records
                if start_time <= r.created_at <= end_time
            ]

            fp_count = 0
            fn_count = 0
            clean_count = 0
            mal_count = 0
            susp_count = 0
            benign_count = 0
            esc_count = 0

            error_dist: dict[str, int] = {}

            for r in window_records:
                verdict_val = r.corrected_verdict.value if hasattr(r.corrected_verdict, "value") else str(r.corrected_verdict)
                error_dist[verdict_val] = error_dist.get(verdict_val, 0) + 1

                if verdict_val == AnalystVerdictCorrection.FALSE_POSITIVE.value:
                    fp_count += 1
                elif verdict_val == AnalystVerdictCorrection.FALSE_NEGATIVE.value:
                    fn_count += 1
                elif verdict_val == AnalystVerdictCorrection.CONFIRMED_CLEAN.value:
                    clean_count += 1
                elif verdict_val == AnalystVerdictCorrection.CONFIRMED_MALICIOUS.value:
                    mal_count += 1
                elif verdict_val == AnalystVerdictCorrection.CONFIRMED_SUSPICIOUS.value:
                    susp_count += 1
                elif verdict_val == AnalystVerdictCorrection.BENIGN_ANOMALY.value:
                    benign_count += 1
                elif verdict_val == AnalystVerdictCorrection.NEEDS_ESCALATION.value:
                    esc_count += 1

            total_samples = len(window_records)

            # FPR = FP / (FP + True Negatives) where True Negatives = Confirmed Clean + Benign Anomaly
            tn_total = clean_count + benign_count
            fpr_denom = fp_count + tn_total
            fpr: float | None = (fp_count / fpr_denom) if fpr_denom > 0 else None

            # FNR = FN / (FN + True Positives) where True Positives = Confirmed Malicious + Confirmed Suspicious
            tp_total = mal_count + susp_count
            fnr_denom = fn_count + tp_total
            fnr: float | None = (fn_count / fnr_denom) if fnr_denom > 0 else None

            return RollingWindowAnalyticsDTO(
                tenant_id=tenant_id,
                window_days=window_days,
                window_start=start_time,
                window_end=end_time,
                sample_count=total_samples,
                false_positive_count=fp_count,
                false_negative_count=fn_count,
                confirmed_clean_count=clean_count,
                confirmed_malicious_count=mal_count,
                confirmed_suspicious_count=susp_count,
                benign_anomaly_count=benign_count,
                needs_escalation_count=esc_count,
                false_positive_rate=fpr,
                false_negative_rate=fnr,
                error_distribution=error_dist,
            )

    async def generate_recommendation(
        self,
        tenant_id: UUID,
        window_days: int = 30,
        current_sensitivity: str | None = None,
        reference_time: datetime | None = None,
    ) -> SensitivityRecommendationDTO:
        """Generate an explainable advisory sensitivity recommendation for a tenant."""
        cur_sens = (current_sensitivity or self.get_tenant_sensitivity(tenant_id)).upper()
        analytics = await self.calculate_window_analytics(
            tenant_id=tenant_id,
            window_days=window_days,
            reference_time=reference_time,
        )

        direction: RecommendationDirection
        rec_sens: str
        reason: str
        explanation: str

        fpr = analytics.false_positive_rate
        fnr = analytics.false_negative_rate
        n = analytics.sample_count

        # 1. Sample Size Safety Check
        if n < self.min_sample_size:
            direction = RecommendationDirection.INSUFFICIENT_DATA
            rec_sens = cur_sens
            reason = "INSUFFICIENT_SAMPLE_SIZE"
            explanation = (
                f"Rolling {window_days}-day window contains {n} feedback sample(s), which is below "
                f"the minimum statistical requirement of {self.min_sample_size}. Policy sensitivity remains at {cur_sens}."
            )
        # 2. High False Positive Rate Rule
        elif fpr is not None and fpr >= HIGH_FPR_THRESHOLD and (fnr is None or fnr < LOW_FNR_THRESHOLD):
            direction = RecommendationDirection.DECREASE_SENSITIVITY
            rec_sens = step_down_sensitivity(cur_sens)
            reason = "HIGH_FALSE_POSITIVE_RATE"
            explanation = (
                f"Observed {window_days}-day False Positive Rate is {fpr * 100:.1f}% across {n} samples "
                f"while False Negative Rate remains low ({fnr * 100 if fnr else 0:.1f}%). "
                f"Recommending bounded step down from {cur_sens} to {rec_sens} to minimize analyst alert fatigue."
            )
        # 3. High False Negative Rate Rule
        elif fnr is not None and fnr >= HIGH_FNR_THRESHOLD and (fpr is None or fpr < LOW_FPR_THRESHOLD):
            direction = RecommendationDirection.INCREASE_SENSITIVITY
            rec_sens = step_up_sensitivity(cur_sens)
            reason = "HIGH_FALSE_NEGATIVE_RATE"
            explanation = (
                f"Observed {window_days}-day False Negative Rate is {fnr * 100:.1f}% across {n} samples "
                f"(exceeds {HIGH_FNR_THRESHOLD * 100:.0f}% threshold). Recommending bounded step up from {cur_sens} "
                f"to {rec_sens} to enhance threat detection posture."
            )
        # 4. Balanced / Tolerable Error Rates Rule
        else:
            direction = RecommendationDirection.MAINTAIN
            rec_sens = cur_sens
            reason = "POLICY_BALANCED"
            fpr_str = f"{fpr * 100:.1f}%" if fpr is not None else "N/A"
            fnr_str = f"{fnr * 100:.1f}%" if fnr is not None else "N/A"
            explanation = (
                f"Observed {window_days}-day error rates (FPR {fpr_str}, FNR {fnr_str}) across {n} samples "
                f"remain within acceptable enterprise operational tolerances. Maintaining {cur_sens} policy setting."
            )

        recommendation = SensitivityRecommendationDTO(
            recommendation_id=uuid4(),
            tenant_id=tenant_id,
            generated_at=datetime.now(UTC),
            window_days=window_days,
            sample_count=n,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            current_sensitivity=cur_sens,
            recommended_sensitivity=rec_sens,
            direction=direction,
            status=RecommendationStatus.PENDING_REVIEW,
            reason=reason,
            explanation=explanation,
        )

        lock = await self._get_tenant_lock(tenant_id)
        async with lock:
            if tenant_id not in self._recommendations:
                self._recommendations[tenant_id] = {}
            self._recommendations[tenant_id][recommendation.recommendation_id] = recommendation

        logger.info(
            "Generated recommendation for tenant %s: direction=%s current=%s recommended=%s",
            tenant_id,
            direction.value,
            cur_sens,
            rec_sens,
        )

        return recommendation

    async def get_tenant_recommendations(
        self, tenant_id: UUID
    ) -> list[SensitivityRecommendationDTO]:
        """Retrieve all generated sensitivity recommendations for a tenant."""
        lock = await self._get_tenant_lock(tenant_id)
        async with lock:
            return list(self._recommendations.get(tenant_id, {}).values())

    async def apply_recommendation(
        self,
        tenant_id: UUID,
        recommendation_id: UUID,
        admin_caller: AuthenticatedAnalystDTO,
    ) -> ApplyRecommendationResponseDTO:
        """Administratively approve and apply a sensitivity recommendation to tenant profile."""
        # 1. Enforce Admin Authorization
        if admin_caller.role.upper() not in ("ADMIN", "SUPER_ADMIN", "LEAD_SOC_ADMIN"):
            raise TunerUnauthorizedError("Only administrative roles can apply sensitivity recommendations")

        # 2. Enforce Tenant Boundary
        if admin_caller.tenant_id != tenant_id:
            raise TunerUnauthorizedError("Caller cannot apply recommendations outside their tenant boundary")

        lock = await self._get_tenant_lock(tenant_id)
        async with lock:
            tenant_recs = self._recommendations.get(tenant_id, {})
            if recommendation_id not in tenant_recs:
                raise RecommendationNotFoundError(
                    f"Recommendation {recommendation_id} not found for tenant {tenant_id}"
                )

            rec = tenant_recs[recommendation_id]

            # 3. Idempotency Check
            if rec.status == RecommendationStatus.APPLIED:
                raise RecommendationAlreadyAppliedError(
                    f"Recommendation {recommendation_id} has already been applied"
                )

            prev_sens = self.get_tenant_sensitivity(tenant_id)
            new_sens = rec.recommended_sensitivity

            # 4. Mutate State & Record Audit Trail
            rec_updated = rec.model_copy(
                update={
                    "status": RecommendationStatus.APPLIED,
                    "applied_by": admin_caller.analyst_id,
                    "applied_at": datetime.now(UTC),
                }
            )
            tenant_recs[recommendation_id] = rec_updated
            self.set_tenant_sensitivity(tenant_id, new_sens)

            logger.info(
                "Applied recommendation %s for tenant %s: %s -> %s by admin %s",
                recommendation_id,
                tenant_id,
                prev_sens,
                new_sens,
                admin_caller.analyst_id,
            )

            return ApplyRecommendationResponseDTO(
                recommendation_id=recommendation_id,
                tenant_id=tenant_id,
                previous_sensitivity=prev_sens,
                new_sensitivity=new_sens,
                applied_by=admin_caller.analyst_id,
                applied_at=datetime.now(UTC),
                message=f"Recommendation successfully applied: tenant sensitivity updated to {new_sens}",
            )
