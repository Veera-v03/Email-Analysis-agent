"""ThreatIntelManager, ThreatIntelProviderRegistry, and ReputationCache implementing enterprise architecture."""

from __future__ import annotations

import time
from collections import OrderedDict
from datetime import UTC, datetime

from src.config.logging import get_logger
from src.security_intelligence.threat_intel.framework import (
    ThreatIntelObservation,
    ThreatIntelProvider,
    ThreatIntelTargetType,
)
from src.security_intelligence.threat_intel.threat_intel_service import (
    LocalThreatIntelProvider,
)
from src.threat_intel.exceptions import CircuitBreakerOpenError
from src.threat_intel.providers.abuseipdb import AbuseIPDBProvider
from src.threat_intel.providers.otx import AlienVaultOTXProvider
from src.threat_intel.providers.virustotal import VirusTotalProvider
from src.threat_intel.resilience.circuit_breaker import (
    ProviderCircuitBreaker,
    ProviderRateLimiter,
)

logger = get_logger("scamon.threat_intel.manager")


class ReputationCacheEntry:
    """Cache entry holding provider reputation observations with TTL."""

    def __init__(
        self, observations: list[ThreatIntelObservation], ttl_seconds: float = 300.0
    ) -> None:
        self.observations = observations
        self.created_at = datetime.now(UTC)
        self.ttl_seconds = ttl_seconds

    def is_expired(self) -> bool:
        """Check if reputation entry has exceeded its TTL."""
        elapsed = (datetime.now(UTC) - self.created_at).total_seconds()
        return elapsed > self.ttl_seconds


class ReputationCache:
    """Thread-safe LRU Reputation Cache supporting URL, Domain, IP, Hash, and Email indicator lookups."""

    def __init__(self, ttl_seconds: float = 300.0, max_size: int = 1000) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self._cache: OrderedDict[str, ReputationCacheEntry] = OrderedDict()

    def get(self, cache_key: str) -> list[ThreatIntelObservation] | None:
        """Retrieve observations from LRU cache if unexpired."""
        if cache_key in self._cache:
            entry = self._cache[cache_key]
            if not entry.is_expired():
                self._cache.move_to_end(cache_key)
                return entry.observations
            del self._cache[cache_key]
        return None

    def put(self, cache_key: str, observations: list[ThreatIntelObservation]) -> None:
        """Add observations to LRU cache, evicting oldest if limit is exceeded."""
        if len(self._cache) >= self.max_size:
            self._cache.popitem(last=False)
        self._cache[cache_key] = ReputationCacheEntry(observations, self.ttl_seconds)
        self._cache.move_to_end(cache_key)


class ThreatIntelProviderRegistry:
    """Registry supporting dynamic registration, lookup, and provider discovery."""

    def __init__(self) -> None:
        self._providers: dict[str, ThreatIntelProvider] = {}

    def register(self, provider: ThreatIntelProvider) -> None:
        """Register a Threat Intelligence provider instance."""
        self._providers[provider.provider_name.lower()] = provider
        logger.info("Registered ThreatIntelProvider: '%s'", provider.provider_name)

    def get_provider(self, name: str) -> ThreatIntelProvider | None:
        """Get provider by name."""
        return self._providers.get(name.lower())

    def get_all_providers(self) -> list[ThreatIntelProvider]:
        """Return list of all registered providers."""
        return list(self._providers.values())


class ThreatIntelManager:
    """Central Threat Intelligence Manager managing provider execution, caching, and resiliency."""

    def __init__(
        self,
        registry: ThreatIntelProviderRegistry | None = None,
        cache: ReputationCache | None = None,
    ) -> None:
        self.registry = registry or ThreatIntelProviderRegistry()
        self.cache = cache or ReputationCache()

        # Circuit breakers & rate limiters per provider
        self.circuit_breakers: dict[str, ProviderCircuitBreaker] = {}
        self.rate_limiters: dict[str, ProviderRateLimiter] = {}

        # Default provider registrations if empty
        if not self.registry.get_all_providers():
            self.registry.register(VirusTotalProvider())
            self.registry.register(AbuseIPDBProvider())
            self.registry.register(AlienVaultOTXProvider())

    def lookup_indicator(
        self, target: str, target_type: ThreatIntelTargetType
    ) -> list[ThreatIntelObservation]:
        """Lookup indicator across all registered providers with caching and resiliency."""
        target_clean = target.strip()
        cache_key = f"{target_type.value}:{target_clean.lower()}"

        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        observations: list[ThreatIntelObservation] = []
        providers = self.registry.get_all_providers()

        for provider in providers:
            p_name = provider.provider_name
            cb = self.circuit_breakers.setdefault(
                p_name, ProviderCircuitBreaker(p_name)
            )
            rl = self.rate_limiters.setdefault(p_name, ProviderRateLimiter())

            if not cb.allow_request():
                logger.warning("[%s] Skipping lookup: Circuit breaker is OPEN", p_name)
                continue

            if not rl.acquire():
                logger.warning("[%s] Skipping lookup: Rate limit reached", p_name)
                continue

            try:
                obs = provider.lookup(target_clean, target_type, timeout_seconds=2.0)
                if obs is not None:
                    observations.append(obs)
                cb.record_success()
            except Exception as exc:
                logger.error("[%s] Provider lookup failed: %s", p_name, exc)
                cb.record_failure()

        self.cache.put(cache_key, observations)
        return observations
