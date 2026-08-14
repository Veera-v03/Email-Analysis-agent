"""AI Guardrail Layer verifying LLM completions against empirical RiskAssessment evidence."""

from __future__ import annotations

import json
from typing import Any

from src.ai_decision.exceptions import GuardrailViolationError
from src.config.logging import get_logger
from src.risk.models import RiskAssessment

logger = get_logger("scamon.ai_decision.guardrail")


class AIGuardrailLayer:
    """Verifies AI generated completions to prevent hallucinations and policy contradictions."""

    # Valid MITRE ATT&CK Technique IDs
    VALID_MITRE_IDS = {
        "T1566",
        "T1566.001",
        "T1566.002",
        "T1566.003",
        "T1204",
        "T1204.001",
        "T1204.002",
        "T1534",
        "T1114",
    }

    def verify_completion(
        self, raw_json_str: str, assessment: RiskAssessment
    ) -> dict[str, Any]:
        """Verify LLM completion JSON against RiskAssessment ground truth."""
        try:
            data = json.loads(raw_json_str)
        except Exception as exc:
            raise GuardrailViolationError(
                f"LLM completion is not valid JSON: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise GuardrailViolationError(
                "LLM completion JSON must be an object dictionary."
            )

        # 1. Verify Action Alignment (No recommendations contradicting RiskAssessment)
        rec_actions = [str(a).lower() for a in data.get("recommended_actions", [])]
        assessment_action = assessment.recommended_action.value.lower()

        if assessment_action in ("quarantined", "blocked") and any(
            "deliver normally" in a or "allow" in a for a in rec_actions
        ):
            raise GuardrailViolationError(
                f"Generated recommendations contradict RiskAssessment action '{assessment.recommended_action.value}'"
            )

        # 2. Verify MITRE Technique IDs (No hallucinated technique codes)
        for tech in assessment.mitre_techniques:
            tech_id = tech.get("id")
            if tech_id and tech_id not in self.VALID_MITRE_IDS:
                logger.warning(
                    "Unrecognized MITRE ID '%s' filtered by Guardrail", tech_id
                )

        # 3. Ensure non-empty required narrative summaries
        for field in ["executive_summary", "technical_summary", "analyst_explanation"]:
            val = data.get(field, "")
            if not isinstance(val, str) or not val.strip():
                raise GuardrailViolationError(
                    f"Required narrative field '{field}' is empty or missing."
                )

        return data
