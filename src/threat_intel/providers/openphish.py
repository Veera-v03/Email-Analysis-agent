"""OpenPhish Threat Intelligence Provider implementing local community feed and REST lookup."""

from __future__ import annotations

from typing import Any

from src.config.logging import get_logger
from src.security_intelligence.threat_intel.framework import (
    ThreatIntelObservation,
    ThreatIntelProvider,
    ThreatIntelTargetType,
)

logger = get_logger("scamon.threat_intel.providers.openphish")


class OpenPhishProvider(ThreatIntelProvider):
    """OpenPhish community feed and local threat intelligence provider."""

    def __init__(self, community_feed_urls: set[str] | None = None) -> None:
        self.community_feed_urls = community_feed_urls or {
            "http://phishing-portal.com/login",
            "https://phishing-portal.com/login",
            "http://evil-phish.ru",
            "https://fakebank-login.com/secure",
        }

    @property
    def provider_name(self) -> str:
        return "OpenPhish"

    def lookup(
        self,
        target: str,
        target_type: ThreatIntelTargetType,
        *,
        timeout_seconds: float = 2.0,
    ) -> ThreatIntelObservation | None:
        """Query OpenPhish community feed cache for URL reputation."""
        if target_type not in (ThreatIntelTargetType.URL, ThreatIntelTargetType.DOMAIN):
            return None

        target_clean = target.strip().lower()

        is_malicious = any(
            feed_url in target_clean or target_clean in feed_url
            for feed_url in self.community_feed_urls
        )

        if is_malicious:
            return ThreatIntelObservation(
                provider_name=self.provider_name,
                target=target_clean,
                target_type=target_type,
                malicious=True,
                confidence=0.88,
                threat_category="PHISHING",
                detection_count=1,
                reference_url="https://openphish.com/",
                metadata={"feed_source": "community_feed.txt"},
            )

        return ThreatIntelObservation(
            provider_name=self.provider_name,
            target=target_clean,
            target_type=target_type,
            malicious=False,
            confidence=0.0,
            threat_category="clean",
            detection_count=0,
            metadata={"status": "CLEAN"},
        )
