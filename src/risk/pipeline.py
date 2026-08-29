"""Multi-stage Enterprise Risk Assessment Pipeline implementing Module 23 Multimodal Fusion."""

from __future__ import annotations

import time
from typing import Any

from src.authentication.models import AuthenticationVerification
from src.config.logging import get_logger
from src.content_intelligence.models import ContentAnalysisResult
from src.parsing.models import ParsedEmail
from src.risk.calibrator import RiskScoreCalibrator
from src.risk.confidence_fusion import ConfidenceFusionEngine
from src.risk.explainability import ExplainabilityGenerator
from src.risk.models import RiskAssessment, RiskPolicyConfig
from src.risk.multimodal_fuser import MultimodalSignalFuser
from src.risk.policy import PolicyEvaluator
from src.risk.profiles import (
    InMemoryTenantRiskProfileProvider,
    ITenantRiskProfileProvider,
    TenantRiskProfile,
)
from src.risk.registry import RiskFeatureRegistry
from src.risk.strategies.base_strategy import IRiskScoringStrategy
from src.risk.strategies.deterministic import DeterministicWeightedScoringStrategy
from src.risk.trend_correlator import (
    DefaultHistoricalRiskCorrelator,
    IHistoricalRiskCorrelator,
)
from src.security_intelligence.risk.risk_enrichment import RiskEnrichmentService
from src.threat_correlation.models import ThreatCorrelationResult
from src.threat_intel.models import ThreatIntelEnrichmentResult
from src.transmission.models import TransmissionAnalysis

logger = get_logger("scamon.risk.pipeline")


class RiskAssessmentPipeline:
    """Orchestrates multimodal feature fusion, scoring, calibration, tenant policy, and explainability."""

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
        fuser: MultimodalSignalFuser | None = None,
        calibrator: RiskScoreCalibrator | None = None,
        profile_provider: ITenantRiskProfileProvider | None = None,
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
        self.fuser = fuser or MultimodalSignalFuser()
        self.calibrator = calibrator or RiskScoreCalibrator()
        self.profile_provider = profile_provider or InMemoryTenantRiskProfileProvider()

    def assess_risk(
        self,
        parsed: ParsedEmail,
        transmission: TransmissionAnalysis,
        auth: AuthenticationVerification,
        intel: ThreatIntelEnrichmentResult,
        content_res: ContentAnalysisResult | None = None,
        url_res: Any | None = None,
        correlation_res: ThreatCorrelationResult | None = None,
        tenant_profile: TenantRiskProfile | None = None,
    ) -> RiskAssessment:
        """Execute complete risk assessment pipeline with multimodal signal fusion and tenant policy."""
        start_time = time.perf_counter()

        # 0. Resolve Tenant Risk Profile
        profile = tenant_profile or self.profile_provider.get_profile(parsed.tenant_id)

        has_multimodal_inputs = any(
            x is not None for x in (content_res, url_res, correlation_res)
        )

        if has_multimodal_inputs and hasattr(
            self.scoring_strategy, "calculate_multimodal_score"
        ):
            # Stage 1: Multimodal Signal Fusion across all 7 intelligence domains
            multimodal_vector = self.fuser.fuse_signals(
                parsed=parsed,
                transmission=transmission,
                auth=auth,
                intel=intel,
                content_res=content_res,
                url_res=url_res,
                correlation_res=correlation_res,
            )
            # Stage 2: Multimodal Scoring Strategy with Domain Ceilings and Anti-Double-Counting
            risk_score, risk_evidence, threat_categories = (
                self.scoring_strategy.calculate_multimodal_score(
                    multimodal_vector=multimodal_vector,
                    config=self.config,
                )
            )
        else:
            # Legacy Module 10 Extraction & Scoring for backward compatibility
            features = self.feature_registry.extract_all_features(
                parsed=parsed, transmission=transmission, auth=auth, intel=intel
            )
            risk_score, risk_evidence, threat_categories = (
                self.scoring_strategy.calculate_score(
                    features=features, config=self.config
                )
            )

        # Include categories from Threat Intel (Module 9)
        all_categories = sorted(list(set(threat_categories + intel.threat_categories)))

        # Stage 3: Closed-Form Sigmoid Probability Calibration
        calibrated_prob = self.calibrator.calibrate(risk_score)

        # Stage 4: Confidence Fusion Engine
        confidence_details = self.confidence_fusion.fuse_confidence(
            parsed=parsed,
            transmission=transmission,
            auth=auth,
            intel=intel,
            evidence_list=risk_evidence,
        )

        # Stage 5: Tenant Policy Evaluation (Verdict & ActionTaken via Tenant Profile)
        verdict, action = profile.evaluate_policy(risk_score)

        # Stage 6: Explainability Generation
        explainability_summary = self.explainability_gen.generate_summary(
            risk_score=risk_score,
            verdict=verdict,
            action=action,
            evidence_list=risk_evidence,
        )

        # Stage 7: MITRE ATT&CK & SOC Mitigations (via RiskEnrichmentService)
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
            calibrated_probability=calibrated_prob,
            verdict=verdict,
            recommended_action=action,
            tenant_profile=profile.sensitivity.value,
            confidence_details=confidence_details,
            risk_evidence=risk_evidence,
            threat_categories=all_categories,
            explainability_summary=explainability_summary,
            mitre_techniques=enrichment_result.get("mitre_attack_mapping", []),
            soc_recommendations=enrichment_result.get("soc_recommendations", []),
            scoring_strategy=self.scoring_strategy.strategy_name,
            assessment_time_ms=elapsed_ms,
        )
