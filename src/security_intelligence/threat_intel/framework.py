"""Optional, normalized threat-intelligence provider framework."""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from src.models.agent import ToolEvidence


class ThreatIntelTargetType(StrEnum):
    """IOC types supported by the normalized provider contract."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    CERTIFICATE = "certificate"


@dataclass(frozen=True)
class ThreatIntelObservation:
    """Provider-neutral reputation observation."""

    provider_name: str
    target: str
    target_type: ThreatIntelTargetType
    malicious: bool = False
    confidence: float | None = None
    threat_category: str = "unknown"
    detection_count: int | None = None
    reference_url: str | None = None
    metadata: dict[str, Any] | None = None


class ThreatIntelProvider(Protocol):
    """Injectable contract for VirusTotal, OTX, MISP, and similar providers."""

    @property
    def provider_name(self) -> str: ...

    def lookup(
        self,
        target: str,
        target_type: ThreatIntelTargetType,
        *,
        timeout_seconds: float,
    ) -> ThreatIntelObservation | None: ...


@dataclass(frozen=True)
class ThreatIntelEnrichment:
    """Outcome of provider fan-out that never raises provider errors."""

    observations: tuple[ThreatIntelObservation, ...] = ()
    diagnostics: tuple[str, ...] = ()
    from_cache: bool = False


class ThreatIntelligenceFramework:
    """Caches, retries, and normalizes optional provider lookups."""

    def __init__(
        self,
        providers: Iterable[ThreatIntelProvider] = (),
        timeout_seconds: float = 2.0,
        retries: int = 0,
        cache_ttl_seconds: float = 300.0,
    ) -> None:
        self._providers = tuple(providers)
        self._timeout_seconds = timeout_seconds
        self._retries = retries
        self._cache_ttl_seconds = cache_ttl_seconds
        self._cache: dict[str, tuple[float, ThreatIntelEnrichment]] = {}

    def enrich(
        self, target: str, target_type: ThreatIntelTargetType
    ) -> ThreatIntelEnrichment:
        """Enrich one IOC, returning diagnostics instead of provider exceptions."""
        cache_key = f"{target_type.value}:{target.casefold()}"
        now = time.monotonic()
        cached = self._cache.get(cache_key)
        if cached and now - cached[0] <= self._cache_ttl_seconds:
            return ThreatIntelEnrichment(
                observations=cached[1].observations,
                diagnostics=cached[1].diagnostics,
                from_cache=True,
            )

        observations: list[ThreatIntelObservation] = []
        diagnostics: list[str] = []
        for provider in self._providers:
            observation, diagnostic = self._lookup(provider, target, target_type)
            if observation is not None:
                observations.append(observation)
            if diagnostic is not None:
                diagnostics.append(diagnostic)
        result = ThreatIntelEnrichment(
            observations=tuple(observations), diagnostics=tuple(diagnostics)
        )
        self._cache[cache_key] = (now, result)
        return result

    def to_evidence(
        self, target: str, target_type: ThreatIntelTargetType
    ) -> tuple[ToolEvidence, ...]:
        """Convert provider results into the existing canonical ToolEvidence form."""
        enrichment = self.enrich(target, target_type)
        evidence: list[ToolEvidence] = []
        for observation in enrichment.observations:
            evidence.append(
                ToolEvidence(
                    category="threat_intelligence",
                    detail=(
                        f"{observation.provider_name} assessed {target_type.value} "
                        f"'{target}' as {observation.threat_category}."
                    ),
                    metadata={
                        "severity": "high" if observation.malicious else "info",
                        "confidence": observation.confidence,
                        "provider": observation.provider_name,
                        "target": target,
                        "target_type": target_type.value,
                        "threat_category": observation.threat_category,
                        "detection_count": observation.detection_count,
                        "reference_url": observation.reference_url,
                        "malicious": observation.malicious,
                        "from_cache": enrichment.from_cache,
                        **(observation.metadata or {}),
                    },
                )
            )
        for diagnostic in enrichment.diagnostics:
            evidence.append(
                ToolEvidence(
                    category="threat_intelligence_diagnostic",
                    detail=diagnostic,
                    metadata={
                        "severity": "info",
                        "target": target,
                        "target_type": target_type.value,
                    },
                )
            )
        return tuple(evidence)

    def _lookup(
        self,
        provider: ThreatIntelProvider,
        target: str,
        target_type: ThreatIntelTargetType,
    ) -> tuple[ThreatIntelObservation | None, str | None]:
        for attempt in range(self._retries + 1):
            try:
                return (
                    provider.lookup(
                        target, target_type, timeout_seconds=self._timeout_seconds
                    ),
                    None,
                )
            except TimeoutError:
                if attempt == self._retries:
                    return None, f"{provider.provider_name}: lookup timed out."
            except Exception as error:
                if attempt == self._retries:
                    return (
                        None,
                        f"{provider.provider_name}: lookup failed "
                        f"({error.__class__.__name__}).",
                    )
        return None, f"{provider.provider_name}: lookup did not complete."
