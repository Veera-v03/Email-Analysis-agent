"""Groq API provider wrapper implementing the LLMProvider interface."""

from __future__ import annotations

import time
from typing import Any

import requests

from src.planner.exceptions.planner_exceptions import ProviderError
from src.planner.interfaces.planner import LLMProvider
from src.planner.models.planner import PlannerUsage, PlanningOptions, ProviderResponse
from src.utils.logging import get_logger

logger = get_logger(__name__)


class GroqProvider(LLMProvider):
    """Concrete implementation of LLMProvider calling Groq completion API."""

    def __init__(
        self,
        api_key: str | None = None,
        default_model: str | None = None,
    ) -> None:
        """Initialize the Groq API client wrapper.

        Args:
            api_key: The authorization bearer token.
            default_model: The model name to use (defaults to GROQ_MODEL in configuration or 'openai/gpt-oss-20b').
        """
        self._api_key = api_key
        if default_model is not None:
            self._default_model = default_model
        else:
            from src.config.enterprise_config import settings

            self._default_model = (
                settings.get_secret("GROQ_MODEL")
                or getattr(settings, "groq_model", "openai/gpt-oss-20b")
            )
        self._endpoint = "https://api.groq.com/openai/v1/chat/completions"

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        options: PlanningOptions | None = None,
    ) -> ProviderResponse:
        """Call the Groq API with configured parameters, handling retries and timeouts.

        Args:
            prompt: The user instruction prompt text.
            system_prompt: Optional instructions for the LLM system role.
            options: Configuration values like temperature, max_tokens, and retries.

        Returns:
            The structured ProviderResponse object.

        Raises:
            ProviderError: If connection, auth, or rate-limiting error occurs.
        """
        if not self._api_key:
            raise ProviderError("Groq API key is not configured.")

        opts = options or PlanningOptions()

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": self._default_model,
            "messages": messages,
            "temperature": opts.temperature,
            "max_tokens": opts.max_tokens,
            "response_format": {"type": "json_object"},
        }

        retry_count = opts.retry_count
        retry_delay = opts.retry_delay
        timeout = opts.timeout

        last_error: ProviderError | None = None

        for attempt in range(retry_count + 1):
            if attempt > 0:
                sleep_time = retry_delay * (2 ** (attempt - 1))
                logger.warning(
                    "Retrying Groq API request. Attempt %d/%d after %s seconds.",
                    attempt,
                    retry_count,
                    sleep_time,
                )
                time.sleep(sleep_time)

            try:
                response = requests.post(
                    self._endpoint,
                    headers=headers,
                    json=payload,
                    timeout=timeout,
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                    except ValueError as e:
                        raise ProviderError(
                            "Failed to parse Groq API response as JSON.",
                            status_code=200,
                            details={"raw_content": response.text, "error": str(e)},
                        ) from e

                    choices = data.get("choices", [])
                    if not choices:
                        raise ProviderError(
                            "Groq API returned an empty choices list.",
                            status_code=200,
                            details={"response": data},
                        )

                    message = choices[0].get("message", {})
                    content = message.get("content")
                    if content is None:
                        raise ProviderError(
                            "Groq API response choice did not contain message content.",
                            status_code=200,
                            details={"choice": choices[0]},
                        )

                    usage_data = data.get("usage", {})
                    usage = PlannerUsage(
                        prompt_tokens=usage_data.get("prompt_tokens"),
                        completion_tokens=usage_data.get("completion_tokens"),
                        total_tokens=usage_data.get("total_tokens"),
                    )

                    return ProviderResponse(
                        content=str(content),
                        usage=usage,
                        metadata={
                            "id": data.get("id"),
                            "model": data.get("model"),
                            "object": data.get("object"),
                        },
                    )

                # Transient errors or rate limit errors
                if response.status_code == 429 or 500 <= response.status_code < 600:
                    retry_after = response.headers.get("Retry-After")
                    if (
                        response.status_code == 429
                        and retry_after
                        and retry_after.isdigit()
                    ):
                        sleep_time = min(int(retry_after), 10)
                        logger.warning(
                            "Groq API 429 rate limit hit. Respecting Retry-After header: waiting %s s",
                            sleep_time,
                        )
                        time.sleep(sleep_time)

                    last_error = ProviderError(
                        f"Groq API transient/rate-limiting error "
                        f"(status code {response.status_code}).",
                        status_code=response.status_code,
                        details={"response_body": response.text},
                    )
                    continue

                # Permanent error
                raise ProviderError(
                    f"Groq API failed with status code {response.status_code}.",
                    status_code=response.status_code,
                    details={"response_body": response.text},
                )

            except requests.exceptions.Timeout as e:
                logger.warning("Groq API request timeout on attempt %d.", attempt)
                last_error = ProviderError(
                    f"Groq API request timed out: {e}",
                    details={"exception": str(e)},
                )
            except requests.exceptions.RequestException as e:
                logger.warning(
                    "Groq API communication failure on attempt %d: %s", attempt, e
                )
                last_error = ProviderError(
                    f"Groq API connection/network error: {e}",
                    details={"exception": str(e)},
                )

        # Retries exhausted
        raise last_error or ProviderError(
            "Groq API request failed after exhausting all attempts."
        )
