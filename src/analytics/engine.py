"""AnalyticsEngine core service for computing multi-tenant threat metrics and security trends."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from src.analytics.exceptions import AnalyticsError
from src.analytics.models import (
    TenantAnalyticsRequestDTO,
    TenantAnalyticsSummaryDTO,
)
from src.config.logging import get_logger
from src.database.db_client import DatabaseClient, db_client
from src.ops.postgres_client import PostgresDatabaseClient

logger = get_logger("scamon.analytics.engine")


class AnalyticsEngine:
    """Enterprise Analytics Engine computing tenant-isolated threat posture metrics."""

    def __init__(
        self,
        database_client: DatabaseClient | None = None,
        postgres_client: PostgresDatabaseClient | None = None,
    ) -> None:
        self.db_client = database_client or db_client
        self.postgres_client = postgres_client or PostgresDatabaseClient()

    def aggregate_tenant_analytics(
        self, request_dto: TenantAnalyticsRequestDTO
    ) -> TenantAnalyticsSummaryDTO:
        """Compute tenant-isolated threat analytics and security metrics."""
        try:
            tenant_id_str = str(request_dto.tenant_id)
            inv_stats = self.db_client.get_tenant_investigation_stats(
                tenant_id=tenant_id_str,
                time_window_hours=request_dto.time_window_hours,
            )

            remediation_stats: dict[str, int] = {}
            if request_dto.include_remediation_summary:
                remediation_stats = self.db_client.get_tenant_remediation_stats(
                    tenant_id=tenant_id_str,
                    time_window_hours=request_dto.time_window_hours,
                )

            summary = TenantAnalyticsSummaryDTO(
                tenant_id=request_dto.tenant_id,
                time_window_hours=request_dto.time_window_hours,
                total_emails_analyzed=inv_stats["total_emails_analyzed"],
                total_threats_detected=inv_stats["total_threats_detected"],
                threat_breakdown_by_verdict=inv_stats["threat_breakdown_by_verdict"],
                remediation_breakdown_by_action=remediation_stats,
                top_threat_senders=inv_stats["top_threat_senders"],
                average_investigation_latency_ms=inv_stats[
                    "average_investigation_latency_ms"
                ],
                generated_at=datetime.now(UTC).isoformat(),
            )
            logger.info(
                "Aggregated tenant analytics for tenant %s (%d threats detected).",
                tenant_id_str,
                summary.total_threats_detected,
            )
            return summary
        except Exception as exc:
            logger.error("Failed to aggregate tenant analytics: %s", exc)
            raise AnalyticsError(
                f"Failed to aggregate tenant analytics: {exc}"
            ) from exc
