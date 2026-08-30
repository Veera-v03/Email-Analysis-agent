"""Targeted unit, contract, resilience, and circuit-breaker tests for Production Hardening Phase 2 (Live Threat Intelligence)."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock
from uuid import uuid4

import httpx
import pytest

from src.common.redis_client import (
    DistributedRateLimiter,
    InMemoryRedisClient,
    ThreatIntelRedisCache,
)
from src.security_intelligence.threat_intel.framework import (
    ThreatIntelObservation,
    ThreatIntelTargetType,
)
from src.threat_intel.providers.live_abuseipdb import LiveAbuseIPDBV2Provider
from src.threat_intel.providers.live_safebrowsing import (
    LiveGoogleSafeBrowsingV4Provider,
)
from src.threat_intel.providers.live_virustotal import LiveVirusTotalV3Provider
from src.threat_intel.resilience.circuit_breaker import (
    CircuitState,
    ProviderCircuitBreaker,
)


# ===========================================================================
# 1. VirusTotal v3 Provider Tests
# ===========================================================================
def test_virustotal_success_malicious_file_hash() -> None:
    mock_response = httpx.Response(
        status_code=200,
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 8,
                        "suspicious": 2,
                        "undetected": 50,
                        "harmless": 10,
                    },
                    "reputation": -50,
                }
            }
        },
        request=httpx.Request("GET", "https://www.virustotal.com/api/v3/files/dummy"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get.return_value = mock_response

    provider = LiveVirusTotalV3Provider(
        api_key="vt_test_secret_key",
        http_client=mock_client,
    )

    obs = provider.lookup(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ThreatIntelTargetType.HASH,
        timeout_seconds=2.0,
    )

    assert obs is not None
    assert obs.provider_name == "VirusTotal_v3"
    assert obs.malicious is True
    assert obs.confidence == 1.0
    assert obs.threat_category == "MALWARE"
    assert obs.detection_count == 10
    assert "vt_test_secret_key" not in str(obs)


def test_virustotal_404_clean_negative() -> None:
    mock_response = httpx.Response(
        status_code=404,
        json={"error": {"code": "NotFoundError", "message": "File not found"}},
        request=httpx.Request("GET", "https://www.virustotal.com/api/v3/files/dummy"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get.return_value = mock_response

    provider = LiveVirusTotalV3Provider(
        api_key="vt_test_key",
        http_client=mock_client,
    )

    obs = provider.lookup(
        "unknown_hash_12345",
        ThreatIntelTargetType.HASH,
        timeout_seconds=2.0,
    )

    assert obs is not None
    assert obs.malicious is False
    assert obs.confidence == 0.0
    # 404 is a valid negative, must NOT trip circuit breaker failure count!
    assert provider.circuit_breaker.failure_count == 0


def test_virustotal_429_and_5xx_records_failure() -> None:
    mock_response_429 = httpx.Response(
        status_code=429,
        json={"error": {"code": "QuotaExceededError"}},
        request=httpx.Request("GET", "https://www.virustotal.com/api/v3/files/dummy"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get.return_value = mock_response_429

    provider = LiveVirusTotalV3Provider(
        api_key="vt_test_key",
        http_client=mock_client,
    )

    obs = provider.lookup(
        "target_hash",
        ThreatIntelTargetType.HASH,
        timeout_seconds=2.0,
    )

    assert obs is None  # Fail-open: returns None
    assert provider.circuit_breaker.failure_count == 1


# ===========================================================================
# 2. Google Safe Browsing v4 Provider Tests
# ===========================================================================
def test_google_safebrowsing_malicious_match() -> None:
    mock_response = httpx.Response(
        status_code=200,
        json={
            "matches": [
                {
                    "threatType": "SOCIAL_ENGINEERING",
                    "platformType": "ANY_PLATFORM",
                    "threatEntryType": "URL",
                    "threat": {"url": "http://evil-phish.com/login"},
                }
            ]
        },
        request=httpx.Request("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.return_value = mock_response

    provider = LiveGoogleSafeBrowsingV4Provider(
        api_key="gsb_test_key",
        http_client=mock_client,
    )

    obs = provider.lookup(
        "http://evil-phish.com/login",
        ThreatIntelTargetType.URL,
        timeout_seconds=2.0,
    )

    assert obs is not None
    assert obs.provider_name == "GoogleSafeBrowsing_v4"
    assert obs.malicious is True
    assert obs.confidence == 0.95
    assert obs.threat_category == "PHISHING"


def test_google_safebrowsing_clean_no_match() -> None:
    mock_response = httpx.Response(
        status_code=200,
        json={},  # Empty dict indicates clean URL in Safe Browsing v4
        request=httpx.Request("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.post.return_value = mock_response

    provider = LiveGoogleSafeBrowsingV4Provider(
        api_key="gsb_test_key",
        http_client=mock_client,
    )

    obs = provider.lookup(
        "https://trusted-portal.com",
        ThreatIntelTargetType.URL,
        timeout_seconds=2.0,
    )

    assert obs is not None
    assert obs.malicious is False
    assert obs.confidence == 0.0
    assert obs.threat_category == "clean"


# ===========================================================================
# 3. AbuseIPDB v2 Provider Tests
# ===========================================================================
def test_abuseipdb_malicious_ip() -> None:
    mock_response = httpx.Response(
        status_code=200,
        json={
            "data": {
                "ipAddress": "198.51.100.44",
                "isPublic": True,
                "ipVersion": 4,
                "abuseConfidenceScore": 85,
                "countryCode": "US",
                "totalReports": 42,
            }
        },
        request=httpx.Request("GET", "https://api.abuseipdb.com/api/v2/check"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get.return_value = mock_response

    provider = LiveAbuseIPDBV2Provider(
        api_key="abuse_test_key",
        http_client=mock_client,
    )

    obs = provider.lookup(
        "198.51.100.44",
        ThreatIntelTargetType.IP,
        timeout_seconds=2.0,
    )

    assert obs is not None
    assert obs.provider_name == "AbuseIPDB_v2"
    assert obs.malicious is True
    assert obs.confidence == 0.85
    assert obs.threat_category == "ABUSE_IP"
    assert obs.detection_count == 42


def test_abuseipdb_clean_ip() -> None:
    mock_response = httpx.Response(
        status_code=200,
        json={
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 0,
                "totalReports": 0,
            }
        },
        request=httpx.Request("GET", "https://api.abuseipdb.com/api/v2/check"),
    )
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get.return_value = mock_response

    provider = LiveAbuseIPDBV2Provider(
        api_key="abuse_test_key",
        http_client=mock_client,
    )

    obs = provider.lookup("8.8.8.8", ThreatIntelTargetType.IP, timeout_seconds=2.0)
    assert obs is not None
    assert obs.malicious is False
    assert obs.confidence == 0.0


# ===========================================================================
# 4. Circuit Breaker Lifecycle Tests (CLOSED -> OPEN -> HALF_OPEN -> CLOSED)
# ===========================================================================
def test_circuit_breaker_state_transitions() -> None:
    cb = ProviderCircuitBreaker(
        provider_name="TestProvider",
        failure_threshold=3,
        recovery_timeout_seconds=0.1,
    )

    # Initial state is CLOSED
    assert cb.state == CircuitState.CLOSED
    assert cb.allow_request() is True

    # 1. Record 2 failures -> Still CLOSED
    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitState.CLOSED
    assert cb.allow_request() is True

    # 2. Record 3rd failure -> Trips to OPEN
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert cb.allow_request() is False

    # 3. Wait for cooldown timeout (100ms)
    asyncio.run(asyncio.sleep(0.12))

    # 4. Probe transitions to HALF_OPEN
    assert cb.allow_request() is True
    assert cb.state == CircuitState.HALF_OPEN

    # 5. Successful probe transitions back to CLOSED
    cb.record_success()
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0


# ===========================================================================
# 5. Redis Cache Integration & Rate Limiting Tests
# ===========================================================================
@pytest.mark.asyncio
async def test_threat_intel_redis_cache_integration() -> None:
    redis_client = InMemoryRedisClient()
    cache = ThreatIntelRedisCache(client=redis_client)

    tenant_id = uuid4()
    target = "https://suspicious-domain.com"
    obs_payload = '{"provider_name": "VirusTotal_v3", "malicious": true, "confidence": 0.9}'

    # Cache Miss -> store observation
    assert await cache.get_observation(tenant_id, "url", target) is None
    await cache.set_observation(tenant_id, "url", target, obs_payload, ttl_sec=3600)

    # Cache Hit
    cached = await cache.get_observation(tenant_id, "url", target)
    assert cached == obs_payload

    # Cross-tenant isolation check: Tenant B gets cache miss
    tenant_b = uuid4()
    assert await cache.get_observation(tenant_b, "url", target) is None


@pytest.mark.asyncio
async def test_threat_intel_distributed_rate_limiting() -> None:
    redis_client = InMemoryRedisClient()
    tenant_id = uuid4()
    limiter = DistributedRateLimiter(
        client=redis_client,
        tenant_id=tenant_id,
        resource_name="virustotal_v3",
        limit=4,
        window_sec=60,
    )

    for _ in range(4):
        allowed, _ = await limiter.is_allowed()
        assert allowed is True

    # 5th request blocked by rate limiter
    allowed_5, _ = await limiter.is_allowed()
    assert allowed_5 is False
