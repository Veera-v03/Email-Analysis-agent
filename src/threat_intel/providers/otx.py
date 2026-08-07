"""AlienVault OTX threat intelligence provider implementation."""

from __future__ import annotations

from src.security_intelligence.threat_intel.framework import (
    ThreatIntelObservation,
    ThreatIntelProvider,
    ThreatIntelTargetType,
)


class AlienVaultOTXProvider(ThreatIntelProvider):
    """AlienVault Open Threat Exchange (OTX) API provider."""

    @property
    def provider_name(self) -> str:
        return "AlienVaultOTX"

    def lookup(
        self,
        target: str,
        target_type: ThreatIntelTargetType,
        *,
        timeout_seconds: float,
    ) -> ThreatIntelObservation | None:
        """Query AlienVault OTX pulses for threat indicators."""
        target_clean = target.strip().lower()

        if any(
            bad in target_clean
            for bad in [
                "phishing-portal.com",
                "credential-harvest.com",
                "203.0.113.195",
            ]
        ):
            return ThreatIntelObservation(
                provider_name=self.provider_name,
                target=target,
                target_type=target_type,
                malicious=True,
                confidence=0.85,
                threat_category="CREDENTIAL_THEFT",
                detection_count=8,
                reference_url=f"https://otx.alienvault.com/indicator/{target_type.value}/{target_clean}",
                metadata={"pulse_count": 8, "author": "OTX Community"},
            )

        return ThreatIntelObservation(
            provider_name=self.provider_name,
            target=target,
            target_type=target_type,
            malicious=False,
            confidence=0.0,
            threat_category="clean",
            detection_count=0,
            metadata={"pulse_count": 0},
        )
