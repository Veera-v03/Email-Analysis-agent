"""Multi-stage Enterprise Risk Assessment Pipeline implementing Module 10 Specification."""

from __future__ import annotations

import time

from src.authentication.models import AuthenticationVerification
from src.config.logging import get_logger
from src.parsing.models import ParsedEmail
from src.risk.confidence_fusion import ConfidenceFusionEngine
from src.risk.explainability import ExplainabilityGenerator
from src.risk.models import RiskAssessment, RiskPolicyConfig
from src.risk.policy import PolicyEvaluator
from src.risk.registry import RiskFeatureRegistry
from src.risk.strategies.base_strategy import IRiskScoringStrategy
from src.risk.strategies.deterministic import DeterministicWeightedScoringStrategy
from src.risk.trend_correlator import (
    DefaultHistoricalRiskCorrelator,
    IHistoricalRiskCorrelator,
)
from src.security_intelligence.risk.risk_enrichment import RiskEnrichmentService
from src.threat_intel.models import ThreatIntelEnrichmentResult
from src.transmission.models import TransmissionAnalysis

logger = get_logger("scamon.risk.pipeline")


class RiskAssessmentPipeline:
    """Orchestrates feature extraction, scoring, confidence fusion, policy, and explainability."""

    def __init__(
        self,
        config: RiskPolicyConfig | None = None,
        feature_registry: RiskFeatureRegistry | None = None,
        scoring_strategy: IRiskScoringStrategy | None = None,
        confidence_fusion: ConfidenceFusionEngine | None = None,
        trend_correlator: IHistoricalRiskCorrelator | None = None,
        policy_evaluator: PolicyEvaluator | None = None,
        explainability_gen: ExplainabilityGenerator | None = None,
        enrichment_service: RiskEnrichmentService | None = None,
    ) -> None:
        self.config = config or RiskPolicyConfig()
        self.feature_registry = feature_registry or RiskFeatureRegistry()
        self.scoring_strategy = (
            scoring_strategy or DeterministicWeightedScoringStrategy()
        )
        self.confidence_fusion = confidence_fusion or ConfidenceFusionEngine()
        self.trend_correlator = trend_correlator or DefaultHistoricalRiskCorrelator()
        self.policy_evaluator = policy_evaluator or PolicyEvaluator(config=self.config)
        self.explainability_gen = explainability_gen or ExplainabilityGenerator()
        self.enrichment_service = enrichment_service or RiskEnrichmentService()

    def assess_risk(
        self,
        parsed: ParsedEmail,
        transmission: TransmissionAnalysis,
        auth: AuthenticationVerification,
        intel: ThreatIntelEnrichmentResult,
    ) -> RiskAssessment:
        """Execute complete risk assessment pipeline across Modules 6-9 outputs."""
        start_time = time.perf_counter()

        # Stage 1: Feature Extraction across Registry
        features = self.feature_registry.extract_all_features(
            parsed=parsed, transmission=transmission, auth=auth, intel=intel
        )

        # Stage 2: Pluggable Risk Scoring Strategy
        risk_score, risk_evidence, threat_categories = (
            self.scoring_strategy.calculate_score(features=features, config=self.config)
        )

        # Include categories from Threat Intel (Module 9)
        all_categories = sorted(list(set(threat_categories + intel.threat_categories)))

        # Stage 3: Confidence Fusion Engine
        confidence_details = self.confidence_fusion.fuse_confidence(
            parsed=parsed,
            transmission=transmission,
            auth=auth,
            intel=intel,
            evidence_list=risk_evidence,
        )

        # Stage 4: Policy Evaluation (Verdict & ActionTaken)
        verdict, action = self.policy_evaluator.evaluate_policy(risk_score)

        # Stage 5: Explainability Generation
        explainability_summary = self.explainability_gen.generate_summary(
            risk_score=risk_score,
            verdict=verdict,
            action=action,
            evidence_list=risk_evidence,
        )

        # Stage 6: MITRE ATT&CK & SOC Mitigations (via RiskEnrichmentService)
        behavioral_input = {
            "detected_tactics": [
                "bec_impersonation"
                if transmission.sender_identity.is_display_name_spoofed
                else "",
                "credential_harvesting"
                if transmission.sender_identity.is_reply_to_mismatched
                else "",
            ]
        }

        enrichment_result = self.enrichment_service.enrich_risk_profile(
            risk_level=verdict.value,
            behavioral_results=behavioral_input,
        )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return RiskAssessment(
            parsed_id=parsed.parsed_id,
            transmission_id=transmission.analysis_id,
            auth_verification_id=auth.verification_id,
            intel_enrichment_id=intel.enrichment_id,
            account_id=parsed.account_id,
            tenant_id=parsed.tenant_id,
            message_id=parsed.message_id,
            risk_score=risk_score,
            verdict=verdict,
            recommended_action=action,
            confidence_details=confidence_details,
            risk_evidence=risk_evidence,
            threat_categories=all_categories,
            explainability_summary=explainability_summary,
            mitre_techniques=enrichment_result.get("mitre_attack_mapping", []),
            soc_recommendations=enrichment_result.get("soc_recommendations", []),
            scoring_strategy=self.scoring_strategy.strategy_name,
            assessment_time_ms=elapsed_ms,
        )
