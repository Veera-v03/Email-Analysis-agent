"""Threat Intelligence & IOC Enrichment Package for ScamON Enterprise."""

from __future__ import annotations

from src.threat_intel.engine import ThreatIntelEngine
from src.threat_intel.exceptions import (
    CircuitBreakerOpenError,
    ProviderLookupError,
    ProviderRateLimitError,
    ThreatIntelError,
)
from src.threat_intel.graph import IOCEdgeDTO, IOCNodeDTO, IOCRelationshipGraph
from src.threat_intel.harvester import IOCHarvester
from src.threat_intel.manager import (
    ReputationCache,
    ThreatIntelManager,
    ThreatIntelProviderRegistry,
)
from src.threat_intel.models import (
    ConfidenceScoreDTO,
    IOCTargetDetailDTO,
    ThreatCategory,
    ThreatIntelEnrichmentResult,
)
from src.threat_intel.module import ThreatIntelModule, register_threat_intel_module
from src.threat_intel.pipeline import ThreatIntelPipeline

__all__ = [
    "CircuitBreakerOpenError",
    "ConfidenceScoreDTO",
    "IOCEdgeDTO",
    "IOCHarvester",
    "IOCNodeDTO",
    "IOCRelationshipGraph",
    "IOCTargetDetailDTO",
    "ProviderLookupError",
    "ProviderRateLimitError",
    "ReputationCache",
    "ThreatCategory",
    "ThreatIntelEngine",
    "ThreatIntelEnrichmentResult",
    "ThreatIntelError",
    "ThreatIntelManager",
    "ThreatIntelModule",
    "ThreatIntelPipeline",
    "ThreatIntelProviderRegistry",
    "register_threat_intel_module",
]
