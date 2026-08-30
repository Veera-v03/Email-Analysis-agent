"""Live Google Safe Browsing API v4 Threat Intelligence provider implementation."""

from __future__ import annotations

import os
from typing import Any

import httpx

from src.config.enterprise_config import settings
from src.config.logging import get_logger
from src.security_intelligence.threat_intel.framework import (
    ThreatIntelObservation,
    ThreatIntelProvider,
    ThreatIntelTargetType,
)
from src.threat_intel.resilience.circuit_breaker import ProviderCircuitBreaker

logger = get_logger("scamon.threat_intel.providers.live_safebrowsing")


class LiveGoogleSafeBrowsingV4Provider(ThreatIntelProvider):
    """Google Safe Browsing API v4 provider querying URLs and domains for known threats."""

    def __init__(
        self,
        api_key: str | None = None,
        endpoint: str | None = None,
        timeout_seconds: float | None = None,
        circuit_breaker: ProviderCircuitBreaker | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key or settings.get_secret("GOOGLE_SAFE_BROWSING_API_KEY")
        self._endpoint = endpoint or getattr(
            settings,
            "google_safe_browsing_endpoint",
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
        )
        self._timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else getattr(settings, "google_safe_browsing_timeout_sec", 2.5)
        )
        self._circuit_breaker = circuit_breaker or ProviderCircuitBreaker(
            provider_name="GoogleSafeBrowsing_v4",
            failure_threshold=getattr(
                settings, "threat_intel_circuit_breaker_threshold", 5
            ),
            recovery_timeout_seconds=getattr(
                settings, "threat_intel_circuit_breaker_cooldown_sec", 60.0
            ),
        )
        self._http_client = http_client

    @property
    def provider_name(self) -> str:
        return "GoogleSafeBrowsing_v4"

    @property
    def circuit_breaker(self) -> ProviderCircuitBreaker:
        return self._circuit_breaker

    def lookup(
        self,
        target: str,
        target_type: ThreatIntelTargetType,
        *,
        timeout_seconds: float,
    ) -> ThreatIntelObservation | None:
        """Query Google Safe Browsing API v4 synchronously."""
        if target_type not in (ThreatIntelTargetType.URL, ThreatIntelTargetType.DOMAIN):
            return None

        if not self._api_key:
            logger.debug("Google Safe Browsing API key not configured; skipping live lookup")
            return None

        if not self._circuit_breaker.allow_request():
            logger.warning(
                "[%s] Circuit breaker is OPEN/cooling down; suppressing outbound call",
                self.provider_name,
            )
            return None

        clean_url = target.strip()
        if target_type == ThreatIntelTargetType.DOMAIN and not clean_url.startswith("http"):
            clean_url = f"https://{clean_url}"

        params = {"key": self._api_key}
        payload = {
            "client": {
                "clientId": "scamon-email-security",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": clean_url}],
            },
        }

        eff_timeout = timeout_seconds or self._timeout_seconds

        try:
            client = self._http_client or httpx.Client(timeout=eff_timeout)
            try:
                resp = client.post(self._endpoint, params=params, json=payload)
            finally:
                if self._http_client is None:
                    client.close()

            # Handle 429
            if resp.status_code == 429:
                logger.warning("[%s] API rate limit reached (429)", self.provider_name)
                self._circuit_breaker.record_failure()
                return None

            if resp.status_code >= 500:
                logger.warning("[%s] Provider 5xx error: %d", self.provider_name, resp.status_code)
                self._circuit_breaker.record_failure()
                return None

            resp.raise_for_status()
            data = resp.json()
            self._circuit_breaker.record_success()

            matches = data.get("matches", [])
            if matches:
                first_match = matches[0]
                threat_type = first_match.get("threatType", "SOCIAL_ENGINEERING")
                category = "PHISHING" if threat_type == "SOCIAL_ENGINEERING" else "MALWARE"
                return ThreatIntelObservation(
                    provider_name=self.provider_name,
                    target=target,
                    target_type=target_type,
                    malicious=True,
                    confidence=0.95,
                    threat_category=category,
                    detection_count=len(matches),
                    metadata={"matches": matches},
                )

            # Valid negative (Clean)
            return ThreatIntelObservation(
                provider_name=self.provider_name,
                target=target,
                target_type=target_type,
                malicious=False,
                confidence=0.0,
                threat_category="clean",
                detection_count=0,
            )
        except (httpx.TimeoutException, httpx.NetworkError) as net_err:
            logger.warning("[%s] Network/Timeout error: %s", self.provider_name, type(net_err).__name__)
            self._circuit_breaker.record_failure()
            return None
        except Exception as exc:
            logger.warning("[%s] Unexpected lookup failure: %s", self.provider_name, type(exc).__name__)
            self._circuit_breaker.record_failure()
            return None
