"""Executive and compliance security report generator for Module 19."""

from __future__ import annotations

import csv
import io
import json
from uuid import uuid4

from src.analytics.exceptions import ReportingError
from src.analytics.models import (
    ExecutiveReportDTO,
    TenantAnalyticsSummaryDTO,
)
from src.config.logging import get_logger

logger = get_logger("scamon.analytics.report_generator")


class ExecutiveReportGenerator:
    """Service generating exportable executive and compliance security reports."""

    @staticmethod
    def generate_report(
        summary: TenantAnalyticsSummaryDTO, report_format: str = "JSON"
    ) -> ExecutiveReportDTO:
        """Generate structured executive security posture report payload."""
        try:
            fmt = report_format.upper().strip()
            if fmt == "JSON":
                report_text = json.dumps(summary.model_dump(mode="json"), indent=2)
            elif fmt == "CSV":
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["Metric Name", "Metric Value"])
                writer.writerow(["tenant_id", str(summary.tenant_id)])
                writer.writerow(["time_window_hours", summary.time_window_hours])
                writer.writerow(
                    ["total_emails_analyzed", summary.total_emails_analyzed]
                )
                writer.writerow(
                    ["total_threats_detected", summary.total_threats_detected]
                )
                writer.writerow(
                    [
                        "average_investigation_latency_ms",
                        f"{summary.average_investigation_latency_ms:.2f}",
                    ]
                )
                writer.writerow(["generated_at", summary.generated_at])
                report_text = output.getvalue()
            elif fmt == "SUMMARY_TEXT":
                report_text = (
                    f"EXECUTIVE SECURITY POSTURE REPORT\n"
                    f"=================================\n"
                    f"Tenant ID: {summary.tenant_id}\n"
                    f"Time Window: {summary.time_window_hours} hours\n"
                    f"Total Emails Analyzed: {summary.total_emails_analyzed}\n"
                    f"Total Threats Detected: {summary.total_threats_detected}\n"
                    f"Avg Latency: {summary.average_investigation_latency_ms:.2f} ms\n"
                    f"Generated At: {summary.generated_at}\n"
                )
            else:
                raise ReportingError(f"Unsupported report format '{report_format}'.")

            compliance = (
                "ATTENTION_REQUIRED"
                if summary.total_threats_detected > 0
                else "COMPLIANT"
            )

            report = ExecutiveReportDTO(
                report_id=uuid4(),
                tenant_id=summary.tenant_id,
                title="Executive Threat & Security Posture Report",
                summary=summary,
                compliance_status=compliance,
                report_format=fmt,
                report_data=report_text,
            )
            logger.info(
                "Generated executive report %s for tenant %s (Format: %s).",
                str(report.report_id),
                str(summary.tenant_id),
                fmt,
            )
            return report
        except Exception as exc:
            logger.error("Failed to generate executive report: %s", exc)
            raise ReportingError(f"Failed to generate executive report: {exc}") from exc
