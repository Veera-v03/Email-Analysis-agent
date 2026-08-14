"""Decision Response Validator parsing and enforcing Pydantic DecisionPlan schema."""

from __future__ import annotations

from typing import Any

from src.ai_decision.exceptions import DecisionValidationError
from src.ai_decision.models import (
    DecisionPlan,
    ExplainabilityProvenanceDTO,
    PromptMetadataDTO,
)
from src.risk.models import RiskAssessment


class DecisionResponseValidator:
    """Parses and validates dictionary completion payload into a strongly typed DecisionPlan DTO."""

    def validate_to_plan(
        self,
        data: dict[str, Any],
        assessment: RiskAssessment,
        provider_name: str,
        execution_time_ms: float,
    ) -> DecisionPlan:
        """Construct immutable DecisionPlan DTO with provenance mappings and metadata."""
        try:
            # Build Explainability Provenance mappings back to supporting evidence
            provenance: list[ExplainabilityProvenanceDTO] = []
            for ev in assessment.risk_evidence:
                provenance.append(
                    ExplainabilityProvenanceDTO(
                        explanation_sentence=ev.explanation,
                        source_module=ev.source_module,
                        supporting_feature=ev.feature_name,
                    )
                )

            # Determine AI decision confidence
            ai_conf = assessment.confidence_details.overall_confidence

            plan = DecisionPlan(
                assessment_id=assessment.assessment_id,
                tenant_id=assessment.tenant_id,
                message_id=assessment.message_id,
                schema_version="1.0.0",
                executive_summary=data.get("executive_summary", ""),
                technical_summary=data.get("technical_summary", ""),
                analyst_explanation=data.get("analyst_explanation", ""),
                attack_summary=data.get(
                    "attack_summary", "Email incident threat analysis"
                ),
                provenance_mappings=provenance,
                mitre_techniques=assessment.mitre_techniques,
                business_impact=data.get(
                    "business_impact", "Potential operational or financial risk"
                ),
                recommended_actions=data.get(
                    "recommended_actions", assessment.soc_recommendations
                ),
                automation_candidates=data.get("automation_candidates", []),
                risk_confidence=assessment.confidence_details.overall_confidence,
                ai_decision_confidence=ai_conf,
                limitations=data.get(
                    "limitations",
                    [
                        "Automated AI decision planning based on risk assessment telemetry."
                    ],
                ),
                prompt_metadata=PromptMetadataDTO(
                    prompt_version="1.0.0",
                    template_version="1.0.0",
                    provider_version=provider_name,
                ),
                generation_time_ms=execution_time_ms,
            )
            return plan
        except Exception as exc:
            raise DecisionValidationError(
                f"Failed to validate DecisionPlan schema: {exc}"
            ) from exc
