"""Unit tests for the Groq LLMProvider implementation."""

from __future__ import annotations

from unittest import mock

import pytest
import requests

from src.planner.exceptions.planner_exceptions import ProviderError
from src.planner.models.planner import PlanningOptions
from src.planner.providers.groq.groq_provider import GroqProvider


def test_groq_provider_requires_api_key() -> None:
    """Ensure that GroqProvider raises ProviderError if initialized without an API key."""
    provider = GroqProvider(api_key=None)
    with pytest.raises(ProviderError) as excinfo:
        provider.generate("prompt")
    assert "key is not configured" in str(excinfo.value)


@mock.patch("requests.post")
def test_groq_provider_success(mock_post: mock.MagicMock) -> None:
    """Verify successful response parsing and token usage mapping."""
    provider = GroqProvider(api_key="test-key", default_model="test-model")

    mock_response = mock.MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "id": "chatcmpl-test",
        "model": "test-model",
        "object": "chat.completion",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": '{"goal": "test"}',
                }
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 20,
            "total_tokens": 30,
        },
    }
    mock_post.return_value = mock_response

    options = PlanningOptions(
        temperature=0.2, max_tokens=100, timeout=10.0, retry_count=0
    )
    result = provider.generate(
        "test-prompt", system_prompt="sys-prompt", options=options
    )

    # Assert request details
    mock_post.assert_called_once_with(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Authorization": "Bearer test-key",
            "Content-Type": "application/json",
        },
        json={
            "model": "test-model",
            "messages": [
                {"role": "system", "content": "sys-prompt"},
                {"role": "user", "content": "test-prompt"},
            ],
            "temperature": 0.2,
            "max_tokens": 100,
            "response_format": {"type": "json_object"},
        },
        timeout=10.0,
    )

    # Assert output parsing
    assert result.content == '{"goal": "test"}'
    assert result.usage.prompt_tokens == 10
    assert result.usage.completion_tokens == 20
    assert result.usage.total_tokens == 30
    assert result.metadata["id"] == "chatcmpl-test"


@mock.patch("requests.post")
def test_groq_provider_retry_on_rate_limit(mock_post: mock.MagicMock) -> None:
    """Verify that GroqProvider retries on rate limits (429) or transient errors (5xx)."""
    provider = GroqProvider(api_key="test-key")

    mock_rate_limit = mock.MagicMock()
    mock_rate_limit.status_code = 429
    mock_rate_limit.text = "Too Many Requests"

    mock_success = mock.MagicMock()
    mock_success.status_code = 200
    mock_success.json.return_value = {
        "choices": [{"message": {"content": "{}"}}],
        "usage": {},
    }

    # First attempt rate limit, second attempt success
    mock_post.side_effect = [mock_rate_limit, mock_success]

    options = PlanningOptions(retry_count=1, retry_delay=0.01)
    result = provider.generate("prompt", options=options)

    assert mock_post.call_count == 2
    assert result.content == "{}"


@mock.patch("requests.post")
def test_groq_provider_rate_limit_failure_exhausted(mock_post: mock.MagicMock) -> None:
    """Ensure that exhaustion of retries raises a ProviderError."""
    provider = GroqProvider(api_key="test-key")

    mock_rate_limit = mock.MagicMock()
    mock_rate_limit.status_code = 429
    mock_rate_limit.text = "Too Many Requests"
    mock_post.return_value = mock_rate_limit

    options = PlanningOptions(retry_count=2, retry_delay=0.01)
    with pytest.raises(ProviderError) as excinfo:
        provider.generate("prompt", options=options)

    assert mock_post.call_count == 3  # Initial + 2 retries
    assert excinfo.value.status_code == 429
    assert "transient/rate-limiting error" in str(excinfo.value)


@mock.patch("requests.post")
def test_groq_provider_timeout_error(mock_post: mock.MagicMock) -> None:
    """Verify timeout mapping of requests.exceptions.Timeout."""
    provider = GroqProvider(api_key="test-key")
    mock_post.side_effect = requests.exceptions.Timeout("Request timed out")

    options = PlanningOptions(retry_count=0)
    with pytest.raises(ProviderError) as excinfo:
        provider.generate("prompt", options=options)

    assert "timed out" in str(excinfo.value)
