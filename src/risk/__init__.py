"""Enterprise Risk Assessment Package for ScamON Enterprise."""

from __future__ import annotations

from src.risk.confidence_fusion import ConfidenceFusionEngine
from src.risk.engine import RiskAssessmentEngine
from src.risk.exceptions import (
    FeatureExtractionError,
    RiskAssessmentError,
    ScoringError,
)
from src.risk.explainability import ExplainabilityGenerator
from src.risk.models import (
    ConfidenceScoreDetailsDTO,
    RiskAssessment,
    RiskEvidenceDTO,
    RiskFeatureVector,
    RiskPolicyConfig,
)
from src.risk.module import RiskAssessmentModule, register_risk_module
from src.risk.pipeline import RiskAssessmentPipeline
from src.risk.policy import PolicyEvaluator
from src.risk.registry import FeatureExtractorProvider, RiskFeatureRegistry
from src.risk.strategies.base_strategy import IRiskScoringStrategy
from src.risk.strategies.deterministic import DeterministicWeightedScoringStrategy
from src.risk.trend_correlator import (
    DefaultHistoricalRiskCorrelator,
    IHistoricalRiskCorrelator,
)

__all__ = [
    "ConfidenceFusionEngine",
    "ConfidenceScoreDetailsDTO",
    "DefaultHistoricalRiskCorrelator",
    "DeterministicWeightedScoringStrategy",
    "ExplainabilityGenerator",
    "FeatureExtractionError",
    "FeatureExtractorProvider",
    "IHistoricalRiskCorrelator",
    "IRiskScoringStrategy",
    "PolicyEvaluator",
    "RiskAssessment",
    "RiskAssessmentEngine",
    "RiskAssessmentError",
    "RiskAssessmentModule",
    "RiskAssessmentPipeline",
    "RiskEvidenceDTO",
    "RiskFeatureRegistry",
    "RiskFeatureVector",
    "RiskPolicyConfig",
    "ScoringError",
    "register_risk_module",
]
