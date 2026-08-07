"""Extension point protocol interface for future historical risk correlation and trend analysis."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from src.risk.models import RiskAssessment


@runtime_checkable
class IHistoricalRiskCorrelator(Protocol):
    """Protocol extension point interface for historical risk trend analysis."""

    def correlate_risk_trend(
        self, tenant_id: Any, sender_address: str, current_score: int
    ) -> dict[str, Any]:
        """Correlate current incident risk score against historical tenant trends."""
        ...


class DefaultHistoricalRiskCorrelator(IHistoricalRiskCorrelator):
    """Default pass-through implementation for historical risk correlation."""

    def correlate_risk_trend(
        self, tenant_id: Any, sender_address: str, current_score: int
    ) -> dict[str, Any]:
        """Return baseline risk trend statistics."""
        return {
            "historical_incident_count": 1,
            "tenant_baseline_risk_avg": float(current_score),
            "trend_direction": "STABLE",
            "is_anomaly_against_tenant_baseline": False,
        }
