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
