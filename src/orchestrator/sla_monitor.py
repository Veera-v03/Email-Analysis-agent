"""SLA Telemetry Monitoring Engine evaluating stage durations against SLA constants."""

from __future__ import annotations

from src.common.constants import (
    SLA_AUTH_VERIFICATION_MAX_MS,
    SLA_DOMAIN_REPUTATION_MAX_MS,
    SLA_HEADER_ANALYZER_MAX_MS,
    SLA_MIME_PARSER_MAX_MS,
    SLA_PIPELINE_LLM_MAX_MS,
    SLA_PIPELINE_STANDARD_MAX_MS,
    SLA_RISK_ENGINE_MAX_MS,
)
from src.config.logging import get_logger

logger = get_logger("scamon.orchestrator.sla")

STAGE_SLA_BUDGETS_MS: dict[str, float] = {
    "mime_parsing": float(SLA_MIME_PARSER_MAX_MS),
    "transmission_analysis": float(SLA_HEADER_ANALYZER_MAX_MS),
    "auth_verification": float(SLA_AUTH_VERIFICATION_MAX_MS),
    "threat_intel": float(SLA_DOMAIN_REPUTATION_MAX_MS),
    "risk_assessment": float(SLA_RISK_ENGINE_MAX_MS),
    "standard_pipeline": float(SLA_PIPELINE_STANDARD_MAX_MS),
    "llm_pipeline": float(SLA_PIPELINE_LLM_MAX_MS),
}


class SLAMonitoringEngine:
    """Tracks and evaluates stage execution durations against enterprise SLA thresholds."""

    def evaluate_sla(
        self, stage_durations_ms: dict[str, float], total_time_ms: float
    ) -> tuple[bool, list[str]]:
        """Evaluate stage durations and return (sla_breached, breached_stages_list)."""
        breached_stages: list[str] = []

        for stage, duration in stage_durations_ms.items():
            budget = STAGE_SLA_BUDGETS_MS.get(stage)
            if budget and duration > budget:
                breached_stages.append(stage)
                logger.warning(
                    "SLA BREACH on stage '%s': %.1fms exceeds budget of %.1fms",
                    stage,
                    duration,
                    budget,
                )

        # Check total pipeline SLA
        pipeline_budget = STAGE_SLA_BUDGETS_MS["llm_pipeline"]
        if total_time_ms > pipeline_budget:
            breached_stages.append("total_pipeline")
            logger.warning(
                "SLA BREACH on total pipeline: %.1fms exceeds budget of %.1fms",
                total_time_ms,
                pipeline_budget,
            )

        sla_breached = len(breached_stages) > 0
        return sla_breached, breached_stages
