"""Header & Transmission Analysis Package for ScamON Enterprise."""

from __future__ import annotations

from src.transmission.engine import TransmissionAnalysisEngine
from src.transmission.exceptions import (
    HopParseError,
    IdentityAnalysisError,
    TransmissionAnalysisError,
)
from src.transmission.models import (
    EvaluatedHopDTO,
    HeaderAnomalyDTO,
    SenderIdentityAnalysisDTO,
    TransmissionAnalysis,
)
from src.transmission.module import TransmissionModule, register_transmission_module
from src.transmission.pipeline import TransmissionAnalysisPipeline

__all__ = [
    "EvaluatedHopDTO",
    "HeaderAnomalyDTO",
    "HopParseError",
    "IdentityAnalysisError",
    "SenderIdentityAnalysisDTO",
    "TransmissionAnalysis",
    "TransmissionAnalysisEngine",
    "TransmissionAnalysisError",
    "TransmissionModule",
    "TransmissionAnalysisPipeline",
    "register_transmission_module",
]
