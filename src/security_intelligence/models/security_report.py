"""Security report model contracts organizing MITRE maps, IOC counts, and verdicts."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class MitreAttackTechnique(BaseModel):
    """Pydantic representation of a single MITRE ATT&CK technique."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    id: str = Field(..., max_length=16)
    name: str = Field(..., max_length=128)
    tactic: str = Field(..., max_length=64)
    description: str = Field(..., max_length=1024)


class EnterpriseSecurityReport(BaseModel):
    """Production-grade enterprise security report consolidating threat vectors, metrics, and IOCs."""

    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)

    executive_summary: str = Field(..., max_length=4096)
    threat_classification: list[str] = Field(default_factory=list)
    mitre_attack_mapping: list[MitreAttackTechnique] = Field(default_factory=list)
    indicators_of_compromise: dict[str, list[str]] = Field(default_factory=dict)
    reputation_threat_intel: dict[str, Any] = Field(default_factory=dict)
    brand_impersonation_analysis: dict[str, Any] = Field(default_factory=dict)
    social_engineering_tactics: list[str] = Field(default_factory=list)
    campaign_correlation: dict[str, Any] = Field(default_factory=dict)
    final_verdict: str = Field(..., max_length=128)
    confidence: float = Field(..., ge=0.0, le=1.0)
    soc_recommendations: list[str] = Field(default_factory=list)
