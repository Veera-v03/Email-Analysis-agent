"""Optional, cached enterprise intelligence enrichment contracts for agent tools."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class IntelligenceObservation:
    """One provider observation about a sender domain or URL."""

    provider_name: str
    summary: str
    malicious: bool = False
    confidence: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IntelligenceDiagnostic:
    """A non-fatal provider lookup diagnostic."""

    provider_name: str
    reason: str


@dataclass(frozen=True, slots=True)
class IntelligenceEnrichment:
    """Cached provider observations and diagnostics for one lookup subject."""

    observations: tuple[IntelligenceObservation, ...] = ()
    diagnostics: tuple[IntelligenceDiagnostic, ...] = ()
    from_cache: bool = False


@runtime_checkable
class EnterpriseIntelligenceProvider(Protocol):
    """Provider contract for optional sender or URL intelligence sources.

    Implementations can represent WHOIS, ASN, reverse DNS, DNSBL, VirusTotal,
    URLHaus, OpenPhish, PhishTank, Safe Browsing, TLS, or other enterprise
    sources. They must honor the supplied timeout when their transport supports
    one and return an observation instead of mutating agent state.
    """

    provider_name: str

    def lookup(
        self,
        subject: str,
        *,
        timeout_seconds: float,
    ) -> IntelligenceObservation | None:
        """Return an observation for the normalized lookup subject."""


class SenderInfrastructureProvider(EnterpriseIntelligenceProvider, Protocol):
    """Marker protocol for sender-domain infrastructure providers."""


class UrlReputationProvider(EnterpriseIntelligenceProvider, Protocol):
    """Marker protocol for URL intelligence and reputation providers."""


class EnterpriseIntelligenceService:
    """Run optional provider lookups with bounded retries and in-memory caching."""

    def __init__(
        self,
        providers: tuple[EnterpriseIntelligenceProvider, ...] = (),
        *,
        timeout_seconds: float = 2.0,
        retries: int = 0,
        cache_ttl_seconds: float = 300.0,
    ) -> None:
        self._providers = providers
        self._timeout_seconds = timeout_seconds
        self._retries = retries
        self._cache_ttl_seconds = cache_ttl_seconds
        self._cache: dict[str, tuple[float, IntelligenceEnrichment]] = {}

    def enrich(self, subject: str) -> IntelligenceEnrichment:
        """Return cached or newly collected provider observations.

        Provider failures are intentionally represented as diagnostics so an
        unavailable external feed cannot fail deterministic email analysis.
        """
        cache_key = subject.casefold()
        cached = self._cache.get(cache_key)
        now = time.monotonic()
        if cached and now - cached[0] <= self._cache_ttl_seconds:
            return IntelligenceEnrichment(
                observations=cached[1].observations,
                diagnostics=cached[1].diagnostics,
                from_cache=True,
            )

        if not self._providers:
            return IntelligenceEnrichment(
                diagnostics=(
                    IntelligenceDiagnostic(
                        provider_name="enterprise_intelligence",
                        reason="No optional intelligence providers are configured.",
                    ),
                ),
            )

        observations: list[IntelligenceObservation] = []
        diagnostics: list[IntelligenceDiagnostic] = []
        for provider in self._providers:
            observation, diagnostic = self._lookup_provider(provider, subject)
            if observation is not None:
                observations.append(observation)
            if diagnostic is not None:
                diagnostics.append(diagnostic)

        enrichment = IntelligenceEnrichment(
            observations=tuple(observations),
            diagnostics=tuple(diagnostics),
        )
        self._cache[cache_key] = (now, enrichment)
        return enrichment

    def _lookup_provider(
        self,
        provider: EnterpriseIntelligenceProvider,
        subject: str,
    ) -> tuple[IntelligenceObservation | None, IntelligenceDiagnostic | None]:
        for attempt in range(self._retries + 1):
            try:
                observation = provider.lookup(
                    subject,
                    timeout_seconds=self._timeout_seconds,
                )
                if observation is None:
                    return None, IntelligenceDiagnostic(
                        provider_name=provider.provider_name,
                        reason="Provider returned no result.",
                    )
                return observation, None
            except TimeoutError:
                if attempt == self._retries:
                    return None, IntelligenceDiagnostic(
                        provider_name=provider.provider_name,
                        reason="Provider lookup timed out.",
                    )
            except Exception as error:
                if attempt == self._retries:
                    return None, IntelligenceDiagnostic(
                        provider_name=provider.provider_name,
                        reason=f"Provider lookup failed: {error.__class__.__name__}.",
                    )
        return None, IntelligenceDiagnostic(
            provider_name=provider.provider_name,
            reason="Provider lookup did not complete.",
        )
