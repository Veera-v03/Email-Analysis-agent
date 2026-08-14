"""Decision Prompt Builder using FileSystemPromptProvider templates and versioning metadata."""

from __future__ import annotations

from typing import Any

from src.ai_decision.models import PromptMetadataDTO
from src.planner.prompts.prompt_provider import FileSystemPromptProvider


class DecisionPromptBuilder:
    """Constructs system and user prompts for AI Decision Planning using templates."""

    def __init__(self, prompt_provider: FileSystemPromptProvider | None = None) -> None:
        self.prompt_provider = prompt_provider or FileSystemPromptProvider()
        self.metadata = PromptMetadataDTO(
            prompt_version="1.0.0",
            template_version="1.0.0",
            provider_version="gemini-1.5-flash",
        )

    def build_prompts(self, context_dict: dict[str, Any]) -> tuple[str, str]:
        """Build (system_prompt, user_prompt) tuple from templates."""
        system_prompt = self.prompt_provider.get_prompt("decision_system_prompt")
        user_prompt = self.prompt_provider.get_prompt(
            "decision_planner_prompt", **context_dict
        )

        return system_prompt, user_prompt
