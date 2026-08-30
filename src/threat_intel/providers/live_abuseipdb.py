"""Live AbuseIPDB API v2 Threat Intelligence provider implementation."""

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

logger = get_logger("scamon.threat_intel.providers.live_abuseipdb")


class LiveAbuseIPDBV2Provider(ThreatIntelProvider):
    """AbuseIPDB API v2 provider checking IP addresses for abuse reports and confidence scores."""

    def __init__(
        self,
        api_key: str | None = None,
        endpoint: str | None = None,
        timeout_seconds: float | None = None,
        circuit_breaker: ProviderCircuitBreaker | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key or settings.get_secret("ABUSEIPDB_API_KEY")
        self._endpoint = endpoint or getattr(
            settings,
            "abuseipdb_endpoint",
            "https://api.abuseipdb.com/api/v2/check",
        )
        self._timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else getattr(settings, "abuseipdb_timeout_sec", 2.5)
        )
        self._circuit_breaker = circuit_breaker or ProviderCircuitBreaker(
            provider_name="AbuseIPDB_v2",
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
        return "AbuseIPDB_v2"

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
        """Query AbuseIPDB API v2 synchronously."""
        if target_type != ThreatIntelTargetType.IP:
            return None

        if not self._api_key:
            logger.debug("AbuseIPDB API key not configured; skipping live lookup")
            return None

        if not self._circuit_breaker.allow_request():
            logger.warning(
                "[%s] Circuit breaker is OPEN/cooling down; suppressing outbound call",
                self.provider_name,
            )
            return None

        headers = {
            "Key": self._api_key,
            "Accept": "application/json",
            "User-Agent": "ScamON-Email-Security/1.0",
        }
        params = {
            "ipAddress": target.strip(),
            "maxAgeInDays": "90",
            "verbose": "",
        }
        eff_timeout = timeout_seconds or self._timeout_seconds

        try:
            client = self._http_client or httpx.Client(timeout=eff_timeout)
            try:
                resp = client.get(self._endpoint, headers=headers, params=params)
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

            ip_data = data.get("data", {})
            abuse_score = int(ip_data.get("abuseConfidenceScore", 0))
            total_reports = int(ip_data.get("totalReports", 0))

            is_mal = abuse_score >= 25
            confidence = min(1.0, abuse_score / 100.0)
            threat_cat = "ABUSE_IP" if is_mal else "clean"

            return ThreatIntelObservation(
                provider_name=self.provider_name,
                target=target,
                target_type=target_type,
                malicious=is_mal,
                confidence=confidence,
                threat_category=threat_cat,
                detection_count=total_reports,
                metadata={
                    "abuseConfidenceScore": abuse_score,
                    "countryCode": ip_data.get("countryCode"),
                    "isp": ip_data.get("isp"),
                    "domain": ip_data.get("domain"),
                },
            )
        except (httpx.TimeoutException, httpx.NetworkError) as net_err:
            logger.warning("[%s] Network/Timeout error: %s", self.provider_name, type(net_err).__name__)
            self._circuit_breaker.record_failure()
            return None
        except Exception as exc:
            logger.warning("[%s] Unexpected lookup failure: %s", self.provider_name, type(exc).__name__)
            self._circuit_breaker.record_failure()
            return None
