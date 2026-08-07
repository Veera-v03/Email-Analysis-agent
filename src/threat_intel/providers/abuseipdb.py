"""AbuseIPDB threat intelligence provider implementation for IP reputation."""

from __future__ import annotations

from src.security_intelligence.threat_intel.framework import (
    ThreatIntelObservation,
    ThreatIntelProvider,
    ThreatIntelTargetType,
)

BLACK_IPS = {"198.51.100.42", "203.0.113.11", "192.0.2.16", "203.0.113.195"}


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB API v2 Threat Intelligence provider."""

    @property
    def provider_name(self) -> str:
        return "AbuseIPDB"

    def lookup(
        self,
        target: str,
        target_type: ThreatIntelTargetType,
        *,
        timeout_seconds: float,
    ) -> ThreatIntelObservation | None:
        """Query AbuseIPDB API / simulated feed for IP reputation."""
        if target_type != ThreatIntelTargetType.IP:
            return None

        target_clean = target.strip()

        if target_clean in BLACK_IPS:
            return ThreatIntelObservation(
                provider_name=self.provider_name,
                target=target,
                target_type=target_type,
                malicious=True,
                confidence=0.90,
                threat_category="C2",
                detection_count=45,
                reference_url=f"https://www.abuseipdb.com/check/{target_clean}",
                metadata={"abuse_confidence_score": 90, "total_reports": 45},
            )

        return ThreatIntelObservation(
            provider_name=self.provider_name,
            target=target,
            target_type=target_type,
            malicious=False,
            confidence=0.0,
            threat_category="clean",
            detection_count=0,
            metadata={"abuse_confidence_score": 0},
        )
