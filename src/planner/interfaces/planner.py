"""Interfaces defining the core abstraction layer of the planning system."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from src.models.agent import AgentState
from src.planner.models.planner import (
    ExecutionPlan,
    PlannerContext,
    PlanningOptions,
    PlanningResult,
    ProviderResponse,
)


class LLMProvider(ABC):
    """Abstract interface for LLM provider wrappers (e.g. Groq, Anthropic, OpenAI)."""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        options: PlanningOptions | None = None,
    ) -> ProviderResponse:
        """Call the LLM provider to generate completion text.

        Uses the given prompts and options.
        """


class PromptProvider(ABC):
    """Abstract interface for managing and loading prompt templates."""

    @abstractmethod
    def get_prompt(self, template_name: str, **kwargs: Any) -> str:
        """Load and format a prompt template by name with provided variables."""


class PlanningPolicy(ABC):
    """Abstract interface for enforcing safety rules and constraints on plans."""

    @abstractmethod
    def validate_plan(self, plan: ExecutionPlan, context: PlannerContext) -> None:
        """Validate the execution plan against the current planning context.

        Raises:
            PlannerError: If the plan violates rules (e.g., calling unregistered tools).
        """


class PlannerContextBuilder(ABC):
    """Abstract interface to build the structured PlannerContext from the AgentState."""

    @abstractmethod
    def build_context(self, state: AgentState) -> PlannerContext:
        """Construct a PlannerContext representation of the current agent state."""


class ExecutionPlanBuilder(ABC):
    """Abstract interface to build the ExecutionPlan from raw parsed dictionary data."""

    @abstractmethod
    def build_plan(self, response_data: dict[str, Any]) -> ExecutionPlan:
        """Parse and construct a strongly typed ExecutionPlan from raw data."""


class Planner(ABC):
    """Abstract orchestrator interface managing the complete planning lifecycle."""

    @abstractmethod
    def plan(
        self,
        state: AgentState,
        options: PlanningOptions | None = None,
    ) -> PlanningResult:
        """Generate a validated PlanningResult given the current state and options."""
