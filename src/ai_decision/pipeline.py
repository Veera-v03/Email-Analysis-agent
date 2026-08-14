"""Multi-stage AI Decision Planning Pipeline implementing Module 11 Specification."""

from __future__ import annotations

import time

from src.ai_decision.context_builder import DecisionContextBuilder
from src.ai_decision.guardrail import AIGuardrailLayer
from src.ai_decision.models import DecisionPlan
from src.ai_decision.prompt_builder import DecisionPromptBuilder
from src.ai_decision.providers.base import ILLMProvider
from src.ai_decision.providers.gemini import GeminiLLMProvider
from src.ai_decision.validator import DecisionResponseValidator
from src.config.logging import get_logger
from src.risk.models import RiskAssessment

logger = get_logger("scamon.ai_decision.pipeline")


class AIDecisionPipeline:
    """Orchestrates context extraction, prompt formatting, LLM generation, guardrails, and validation."""

    def __init__(
        self,
        llm_provider: ILLMProvider | None = None,
        context_builder: DecisionContextBuilder | None = None,
        prompt_builder: DecisionPromptBuilder | None = None,
        guardrail: AIGuardrailLayer | None = None,
        validator: DecisionResponseValidator | None = None,
    ) -> None:
        self.llm_provider = llm_provider or GeminiLLMProvider()
        self.context_builder = context_builder or DecisionContextBuilder()
        self.prompt_builder = prompt_builder or DecisionPromptBuilder()
        self.guardrail = guardrail or AIGuardrailLayer()
        self.validator = validator or DecisionResponseValidator()

    async def plan_decision(self, assessment: RiskAssessment) -> DecisionPlan:
        """Execute complete AI Decision Planning pipeline on RiskAssessment DTO."""
        start_time = time.perf_counter()

        # Stage 1: Build Context Dictionary
        context_dict = self.context_builder.build_context_dict(assessment)

        # Stage 2: Build System & User Prompts
        system_prompt, user_prompt = self.prompt_builder.build_prompts(context_dict)

        # Stage 3: Call ILLMProvider
        raw_completion = await self.llm_provider.generate_completion(
            system_prompt=system_prompt, user_prompt=user_prompt
        )

        # Stage 4: AI Guardrail Verification
        sanitized_dict = self.guardrail.verify_completion(raw_completion, assessment)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Stage 5: Response Schema Validation
        return self.validator.validate_to_plan(
            data=sanitized_dict,
            assessment=assessment,
            provider_name=self.llm_provider.provider_name,
            execution_time_ms=elapsed_ms,
        )
