"""Threat Correlation & Campaign Intelligence Package for ScamON Enterprise."""

from __future__ import annotations

from src.threat_correlation.engine import ThreatCorrelationEngine
from src.threat_correlation.exceptions import ThreatCorrelationError
from src.threat_correlation.graph_builder import IOCGraphBuilder
from src.threat_correlation.models import (
    IOCRelationshipGraphDTO,
    ThreatCorrelationResult,
)
from src.threat_correlation.module import (
    ThreatCorrelationModule,
    register_threat_correlation_module,
)
from src.threat_correlation.pipeline import ThreatCorrelationPipeline

__all__ = [
    "IOCGraphBuilder",
    "IOCRelationshipGraphDTO",
    "ThreatCorrelationEngine",
    "ThreatCorrelationError",
    "ThreatCorrelationModule",
    "ThreatCorrelationPipeline",
    "ThreatCorrelationResult",
    "register_threat_correlation_module",
]
