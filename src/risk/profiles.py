"""Tenant risk profile models, sensitivity policies, and profile resolution provider (Module 23)."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol
from uuid import UUID

from pydantic import Field

from src.common.constants import ActionTaken, Verdict
from src.common.models import BaseDTO


class TenantRiskSensitivity(StrEnum):
    """Tenant risk sensitivity classification."""

    AGGRESSIVE = "AGGRESSIVE"  # High sensitivity: lower thresholds for SUSPICIOUS / MALICIOUS
    BALANCED = "BALANCED"      # Standard enterprise baseline (Default)
    PERMISSIVE = "PERMISSIVE"  # Low false-positive tolerance: higher thresholds for MALICIOUS


class TenantRiskProfile(BaseDTO):
    """Immutable, strongly typed tenant-scoped risk profile configuration."""

    tenant_id: UUID = Field(description="Associated enterprise tenant UUID")
    sensitivity: TenantRiskSensitivity = Field(
        default=TenantRiskSensitivity.BALANCED,
        description="Tenant sensitivity policy setting",
    )
    threshold_clean_max: int = Field(
        default=29,
        ge=0,
        le=100,
        description="Max risk score to classify as CLEAN",
    )
    threshold_suspicious_max: int = Field(
        default=69,
        ge=0,
        le=100,
        description="Max risk score to classify as SUSPICIOUS (above is MALICIOUS)",
    )
    threshold_malicious_quarantine_max: int = Field(
        default=89,
        ge=0,
        le=100,
        description="Max score for QUARANTINE before BLOCKED",
    )
    enforce_quarantine_on_suspicious: bool = Field(
        default=False,
        description="If True, SUSPICIOUS emails are QUARANTINED rather than BANNER_INJECTED",
    )
    profile_version: str = Field(default="1.0.0", description="Profile schema version")

    def evaluate_policy(self, risk_score: int) -> tuple[Verdict, ActionTaken]:
        """Map deterministic risk score (0-100) to Verdict and ActionTaken per tenant thresholds."""
        if risk_score <= self.threshold_clean_max:
            return Verdict.CLEAN, ActionTaken.DELIVERED
        elif risk_score <= self.threshold_suspicious_max:
            action = (
                ActionTaken.QUARANTINED
                if self.enforce_quarantine_on_suspicious
                else ActionTaken.BANNER_INJECTED
            )
            return Verdict.SUSPICIOUS, action
        elif risk_score <= self.threshold_malicious_quarantine_max:
            return Verdict.MALICIOUS, ActionTaken.QUARANTINED
        else:
            return Verdict.MALICIOUS, ActionTaken.BLOCKED

    @classmethod
    def create_default(cls, tenant_id: UUID) -> TenantRiskProfile:
        """Create standard balanced profile for a tenant."""
        return cls(tenant_id=tenant_id, sensitivity=TenantRiskSensitivity.BALANCED)

    @classmethod
    def create_aggressive(cls, tenant_id: UUID) -> TenantRiskProfile:
        """Create aggressive high-security sensitivity profile (Financial / Executive mailboxes)."""
        return cls(
            tenant_id=tenant_id,
            sensitivity=TenantRiskSensitivity.AGGRESSIVE,
            threshold_clean_max=19,
            threshold_suspicious_max=49,
            threshold_malicious_quarantine_max=79,
            enforce_quarantine_on_suspicious=True,
        )

    @classmethod
    def create_balanced(cls, tenant_id: UUID) -> TenantRiskProfile:
        """Create standard balanced enterprise sensitivity profile."""
        return cls(
            tenant_id=tenant_id,
            sensitivity=TenantRiskSensitivity.BALANCED,
            threshold_clean_max=29,
            threshold_suspicious_max=69,
            threshold_malicious_quarantine_max=89,
            enforce_quarantine_on_suspicious=False,
        )

    @classmethod
    def create_permissive(cls, tenant_id: UUID) -> TenantRiskProfile:
        """Create permissive sensitivity profile (High-volume marketing / ops)."""
        return cls(
            tenant_id=tenant_id,
            sensitivity=TenantRiskSensitivity.PERMISSIVE,
            threshold_clean_max=39,
            threshold_suspicious_max=79,
            threshold_malicious_quarantine_max=94,
            enforce_quarantine_on_suspicious=False,
        )


class ITenantRiskProfileProvider(Protocol):
    """Protocol interface for resolving tenant risk profiles."""

    def get_profile(self, tenant_id: UUID) -> TenantRiskProfile: ...
    def set_profile(self, profile: TenantRiskProfile) -> None: ...


class InMemoryTenantRiskProfileProvider:
    """Thread-safe in-memory provider resolving TenantRiskProfiles by tenant_id."""

    def __init__(self) -> None:
        self._profiles: dict[UUID, TenantRiskProfile] = {}

    def get_profile(self, tenant_id: UUID) -> TenantRiskProfile:
        """Retrieve tenant profile by tenant_id or return default balanced profile."""
        if tenant_id in self._profiles:
            return self._profiles[tenant_id]
        return TenantRiskProfile.create_balanced(tenant_id)

    def set_profile(self, profile: TenantRiskProfile) -> None:
        """Register or update a tenant profile."""
        self._profiles[profile.tenant_id] = profile
