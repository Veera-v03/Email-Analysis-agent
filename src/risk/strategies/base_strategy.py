"""IRiskScoringStrategy protocol interface for pluggable risk scoring algorithms."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from src.risk.models import RiskEvidenceDTO, RiskPolicyConfig


@runtime_checkable
class IRiskScoringStrategy(Protocol):
    """Protocol interface for pluggable risk scoring strategies (Deterministic, ML, Hybrid)."""

    @property
    def strategy_name(self) -> str: ...

    def calculate_score(
        self,
        features: dict[str, Any],
        config: RiskPolicyConfig,
    ) -> tuple[int, list[RiskEvidenceDTO], list[str]]:
        """Calculate risk score, return (risk_score, risk_evidence_list, threat_categories)."""
        ...
