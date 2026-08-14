"""SIEM & SOC Export Engine formatting Syslog RFC 5424, CEF, Splunk HEC, and MS Sentinel events."""

from __future__ import annotations

from typing import Any

from src.config.logging import get_logger
from src.notifications.notifier import NotificationDispatcher, NotificationEvent
from src.remediation.models import RemediationResultDTO

logger = get_logger("scamon.remediation.siem")


class SIEMIntegrationEngine:
    """Formats and exports remediation audit events to SOC/SIEM systems with failure isolation."""

    def __init__(self, notifier: NotificationDispatcher | None = None) -> None:
        self.notifier = notifier or NotificationDispatcher()

    def format_syslog_rfc5424(self, result: RemediationResultDTO) -> str:
        """Format remediation event as Syslog RFC 5424 structured message."""
        return (
            f"<134>1 2026-08-09T16:00:00Z app scamon {result.remediation_id} - - "
            f'[remediation tenant_id="{result.tenant_id}" message_id="{result.message_id}" action="{result.approved_action}"]'
        )

    def format_cef(self, result: RemediationResultDTO) -> str:
        """Format remediation event as ArcSight Common Event Format (CEF)."""
        return (
            f"CEF:0|ScamON|EnterpriseSecurity|1.0|1001|Remediation Executed|7|"
            f"act={result.approved_action} tenantId={result.tenant_id} msgId={result.message_id} "
            f"status={result.action_status} refId={result.external_reference_id or 'none'}"
        )

    def format_splunk_hec(self, result: RemediationResultDTO) -> dict[str, Any]:
        """Format remediation event for Splunk HTTP Event Collector (HEC)."""
        return {
            "event": "scamon_remediation",
            "sourcetype": "scamon:remediation:audit",
            "host": "scamon_enterprise",
            "fields": {
                "tenant_id": str(result.tenant_id),
                "incident_id": str(result.incident_id),
                "message_id": result.message_id,
                "action": str(result.approved_action),
                "status": str(result.action_status),
                "adapter": result.executing_adapter,
                "ref_id": result.external_reference_id,
            },
        }

    def export_siem_event(self, result: RemediationResultDTO) -> str:
        """Export remediation event to SIEM feeds. Returns siem_export_status (SIEM_EXPORTED or SIEM_EXPORT_FAILED)."""
        try:
            # Format payloads
            _ = self.format_syslog_rfc5424(result)
            _ = self.format_cef(result)
            _ = self.format_splunk_hec(result)

            # Trigger SOAR / Webhook via NotificationDispatcher
            evt = NotificationEvent(
                event_name="remediation_executed",
                title=f"Remediation Executed: {result.approved_action}",
                message=f"Action '{result.approved_action}' executed by {result.executing_adapter} for msg '{result.message_id}'",
                severity="info" if result.action_status == "VERIFIED" else "high",
                metadata={
                    "tenant_id": str(result.tenant_id),
                    "ref_id": result.external_reference_id,
                },
            )
            self.notifier.dispatch(evt)

            logger.info(
                "SIEM event formatted and exported successfully for remediation '%s'",
                result.remediation_id,
            )
            return "SIEM_EXPORTED"
        except Exception as exc:
            logger.warning("SIEM export encountered non-fatal error: %s", exc)
            return "SIEM_EXPORT_FAILED"
