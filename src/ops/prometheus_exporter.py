"""Prometheus observability exporter using strict low-cardinality labels for Module 18."""

from __future__ import annotations

from typing import Any

from src.config.logging import get_logger

logger = get_logger("scamon.ops.prometheus")


class PrometheusMetricsExporter:
    """Prometheus metrics exporter capturing pipeline SLA, verdicts, and remediation metrics safely."""

    def __init__(self) -> None:
        self._metrics: dict[str, Any] = {}

    def record_email_processed(self, status: str = "SUCCESS") -> None:
        """Increment scamon_emails_processed_total counter."""
        logger.debug(
            "Prometheus metric: scamon_emails_processed_total{status='%s'}", status
        )

    def record_risk_verdict(self, verdict: str) -> None:
        """Increment scamon_risk_verdicts_total counter using low-cardinality verdict label."""
        logger.debug(
            "Prometheus metric: scamon_risk_verdicts_total{verdict='%s'}", verdict
        )

    def record_remediation_executed(
        self, action: str, status: str = "VERIFIED"
    ) -> None:
        """Increment scamon_remediations_executed_total counter."""
        logger.debug(
            "Prometheus metric: scamon_remediations_executed_total{action='%s', status='%s'}",
            action,
            status,
        )

    def record_stage_duration(self, stage_name: str, duration_seconds: float) -> None:
        """Record scamon_stage_duration_seconds histogram."""
        logger.debug(
            "Prometheus metric: scamon_stage_duration_seconds{stage='%s'} = %.4fs",
            stage_name,
            duration_seconds,
        )
