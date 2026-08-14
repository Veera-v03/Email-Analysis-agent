"""Security detection and analysis event contract payloads matching SAS v1.1.0."""

from __future__ import annotations

from uuid import UUID

from pydantic import Field

from src.common.constants import ActionTaken, Verdict
from src.events.base_event import BaseEvent


class AuthEvaluatedEvent(BaseEvent):
    """Event emitted after evaluating SPF, DKIM, DMARC, and ARC authentication."""

    event_type: str = "scamon.prod.auth.evaluated.v1"
    message_id: str = Field(description="Internal message identifier")
    spf_result: str = Field(
        description="SPF result: PASS, FAIL, SOFTFAIL, NEUTRAL, NONE"
    )
    dkim_result: str = Field(description="DKIM result: PASS, FAIL, NONE")
    dmarc_result: str = Field(description="DMARC result: PASS, FAIL, NONE")
    arc_chain_valid: bool = Field(default=False, description="ARC chain validity flag")


class IntelEnrichedEvent(BaseEvent):
    """Event emitted when IOCs are enriched against threat intelligence feeds."""

    event_type: str = "scamon.prod.intel.enriched.v1"
    message_id: str = Field(description="Internal message identifier")
    malicious_ioc_count: int = Field(
        default=0, description="Count of matched malicious IOCs"
    )
    confidence_score: float = Field(
        default=0.0, description="Aggregated threat feed confidence score"
    )
    matched_feeds: list[str] = Field(
        default_factory=list, description="Names of matched threat feeds"
    )


class ThreatCorrelatedEvent(BaseEvent):
    """Event emitted when threat correlation and campaign clustering are evaluated."""

    event_type: str = "scamon.prod.threat.correlated.v1"
    message_id: str = Field(description="Internal message identifier")
    campaign_detected: bool = Field(
        default=False, description="Flag indicating campaign cluster match"
    )
    campaign_score: float = Field(default=0.0, description="Campaign correlation score")
    correlated_iocs_count: int = Field(
        default=0, description="Count of correlated graph IOC nodes"
    )
    mitre_technique_count: int = Field(
        default=0, description="Count of mapped MITRE ATT&CK techniques"
    )


class RemediationExecutedEvent(BaseEvent):
    """Event emitted when a security remediation action is executed."""

    event_type: str = "scamon.prod.remediation.executed.v1"
    message_id: str = Field(description="Internal message identifier")
    action_taken: ActionTaken = Field(description="Enforced remediation action")
    adapter_name: str = Field(description="Executing adapter plugin name")
    external_reference_id: str | None = Field(
        default=None, description="External provider reference ID"
    )
    status: str = Field(description="Execution status: SUCCESS, FAILED, DRY_RUN")


class RemediationPendingApprovalEvent(BaseEvent):
    """Event emitted when a high-impact remediation action requires human approval."""

    event_type: str = "scamon.prod.remediation.pending_approval.v1"
    message_id: str = Field(description="Internal message identifier")
    requested_action: ActionTaken = Field(description="Requested high-impact action")
    reason: str = Field(description="Reason requiring human authorization")


class RiskScoredEvent(BaseEvent):
    """Event emitted when final risk score and verdict are calculated."""

    event_type: str = "scamon.prod.risk.scored.v1"
    incident_id: UUID = Field(description="Associated incident record UUID")
    message_id: str = Field(description="Internal message identifier")
    risk_score: int = Field(ge=0, le=100, description="Consolidated risk score (0-100)")
    verdict: Verdict = Field(description="Final threat verdict classification")
    threat_categories: list[str] = Field(
        default_factory=list, description="Matched attack categories"
    )
    recommended_action: ActionTaken = Field(description="Remediation policy action")
    explainability_summary: str = Field(description="Human readable explanation text")


class AnalyticsAggregatedEvent(BaseEvent):
    """Security event published when tenant threat analytics are aggregated."""

    event_type: str = "scamon.prod.analytics.aggregated.v1"
    time_window_hours: int = Field(default=24, description="Evaluation window in hours")
    total_emails_analyzed: int = Field(default=0, ge=0, description="Total analyzed")
    total_threats_detected: int = Field(default=0, ge=0, description="Total threats")
    remediations_executed: int = Field(default=0, ge=0, description="Total SOC actions")
