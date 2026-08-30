"""Live VirusTotal API v3 Threat Intelligence provider implementation with rate limiting and circuit breakers."""

from __future__ import annotations

import base64
import os
import re
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

logger = get_logger("scamon.threat_intel.providers.live_virustotal")


class LiveVirusTotalV3Provider(ThreatIntelProvider):
    """Production VirusTotal API v3 provider querying hashes, domains, IPs, and URLs."""

    def __init__(
        self,
        api_key: str | None = None,
        endpoint: str | None = None,
        timeout_seconds: float | None = None,
        circuit_breaker: ProviderCircuitBreaker | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._api_key = api_key or settings.get_secret("VIRUSTOTAL_API_KEY")
        self._endpoint = endpoint or getattr(
            settings, "virustotal_endpoint", "https://www.virustotal.com/api/v3"
        ).rstrip("/")
        self._timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else getattr(settings, "virustotal_timeout_sec", 3.0)
        )
        self._circuit_breaker = circuit_breaker or ProviderCircuitBreaker(
            provider_name="VirusTotal_v3",
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
        return "VirusTotal_v3"

    @property
    def circuit_breaker(self) -> ProviderCircuitBreaker:
        return self._circuit_breaker

    @staticmethod
    def _encode_url_id(url: str) -> str:
        """VirusTotal v3 requires URLs to be base64url-encoded without padding."""
        return base64.urlsafe_b64encode(url.strip().encode("utf-8")).decode("ascii").rstrip("=")

    def _build_url(self, target: str, target_type: ThreatIntelTargetType) -> str:
        clean_target = target.strip()
        if target_type == ThreatIntelTargetType.HASH:
            return f"{self._endpoint}/files/{clean_target.lower()}"
        elif target_type == ThreatIntelTargetType.DOMAIN:
            return f"{self._endpoint}/domains/{clean_target.lower()}"
        elif target_type == ThreatIntelTargetType.IP:
            return f"{self._endpoint}/ip_addresses/{clean_target}"
        elif target_type == ThreatIntelTargetType.URL:
            url_id = self._encode_url_id(clean_target)
            return f"{self._endpoint}/urls/{url_id}"
        return f"{self._endpoint}/files/{clean_target}"

    def lookup(
        self,
        target: str,
        target_type: ThreatIntelTargetType,
        *,
        timeout_seconds: float,
    ) -> ThreatIntelObservation | None:
        """Query VirusTotal API v3 synchronously or return safe fallback if unconfigured or circuit is open."""
        if not self._api_key:
            logger.debug("VirusTotal API key not configured; skipping live lookup")
            return None

        if not self._circuit_breaker.allow_request():
            logger.warning(
                "[%s] Circuit breaker is OPEN/cooling down; suppressing outbound call",
                self.provider_name,
            )
            return None

        url = self._build_url(target, target_type)
        headers = {
            "x-apikey": self._api_key,
            "Accept": "application/json",
            "User-Agent": "ScamON-Email-Security/1.0",
        }
        eff_timeout = timeout_seconds or self._timeout_seconds

        try:
            client = self._http_client or httpx.Client(timeout=eff_timeout)
            try:
                resp = client.get(url, headers=headers)
            finally:
                if self._http_client is None:
                    client.close()

            # Handle 404: Valid negative result (not an infrastructure failure)
            if resp.status_code == 404:
                self._circuit_breaker.record_success()
                return ThreatIntelObservation(
                    provider_name=self.provider_name,
                    target=target,
                    target_type=target_type,
                    malicious=False,
                    confidence=0.0,
                    threat_category="unknown",
                    detection_count=0,
                )

            # Handle 429: Rate Limit
            if resp.status_code == 429:
                logger.warning("[%s] API rate limit reached (429)", self.provider_name)
                self._circuit_breaker.record_failure()
                return None

            # Handle 5xx / other errors
            if resp.status_code >= 500:
                logger.warning("[%s] Provider 5xx error: %d", self.provider_name, resp.status_code)
                self._circuit_breaker.record_failure()
                return None

            resp.raise_for_status()
            data = resp.json()
            self._circuit_breaker.record_success()

            attributes = data.get("data", {}).get("attributes", {})
            last_stats = attributes.get("last_analysis_stats", {})
            malicious_count = int(last_stats.get("malicious", 0))
            suspicious_count = int(last_stats.get("suspicious", 0))
            total_detections = malicious_count + suspicious_count

            is_mal = malicious_count >= 3 or total_detections >= 5
            confidence = min(1.0, max(0.5, total_detections / 10.0)) if is_mal else 0.0
            threat_cat = "MALWARE" if target_type == ThreatIntelTargetType.HASH else "PHISHING" if is_mal else "clean"

            return ThreatIntelObservation(
                provider_name=self.provider_name,
                target=target,
                target_type=target_type,
                malicious=is_mal,
                confidence=confidence,
                threat_category=threat_cat,
                detection_count=total_detections,
                metadata={
                    "last_analysis_stats": last_stats,
                    "reputation": attributes.get("reputation", 0),
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
