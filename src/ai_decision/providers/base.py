"""ILLMProvider protocol interface and LLM Retry Strategy for ScamON Enterprise."""

from __future__ import annotations

import asyncio
from typing import Any, Protocol, runtime_checkable

from src.config.logging import get_logger

logger = get_logger("scamon.ai_decision.providers")


@runtime_checkable
class ILLMProvider(Protocol):
    """Protocol interface for LLM provider wrappers (Gemini, OpenAI, Anthropic, Ollama)."""

    @property
    def provider_name(self) -> str: ...

    async def generate_completion(
        self, system_prompt: str, user_prompt: str, temperature: float = 0.1
    ) -> str: ...


class LLMRetryStrategy:
    """Configurable retry strategy supporting timeout, exponential backoff, and max retries."""

    def __init__(
        self,
        timeout_seconds: float = 5.0,
        max_retries: int = 2,
        backoff_factor: float = 1.5,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

    async def execute_with_retry(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        """Execute async function with retries and exponential backoff."""
        last_exception = None
        delay = 1.0

        for attempt in range(self.max_retries + 1):
            try:
                return await asyncio.wait_for(
                    func(*args, **kwargs), timeout=self.timeout_seconds
                )
            except Exception as exc:
                last_exception = exc
                logger.warning(
                    "LLM provider attempt %d/%d failed: %s. Retrying in %.1fs...",
                    attempt + 1,
                    self.max_retries + 1,
                    exc,
                    delay,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(delay)
                    delay *= self.backoff_factor

        raise last_exception or RuntimeError("LLM provider retries exhausted")
