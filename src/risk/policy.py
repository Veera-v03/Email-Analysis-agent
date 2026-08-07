"""Policy Evaluator mapping calculated risk score to Verdict and ActionTaken using RiskPolicyConfig."""

from __future__ import annotations

from src.common.constants import ActionTaken, Verdict
from src.risk.models import RiskPolicyConfig


class PolicyEvaluator:
    """Evaluates final risk score against configurable enterprise policy boundaries."""

    def __init__(self, config: RiskPolicyConfig | None = None) -> None:
        self.config = config or RiskPolicyConfig()

    def evaluate_policy(self, risk_score: int) -> tuple[Verdict, ActionTaken]:
        """Map score (0-100) to Verdict and ActionTaken according to RiskPolicyConfig."""
        if risk_score <= self.config.threshold_clean_max:
            return Verdict.CLEAN, ActionTaken.DELIVERED
        elif risk_score <= self.config.threshold_suspicious_max:
            return Verdict.SUSPICIOUS, ActionTaken.BANNER_INJECTED
        elif risk_score <= self.config.threshold_malicious_quarantine_max:
            return Verdict.MALICIOUS, ActionTaken.QUARANTINED
        else:
            return Verdict.MALICIOUS, ActionTaken.BLOCKED
