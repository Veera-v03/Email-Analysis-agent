"""Wrapper for planner settings mapping."""

from __future__ import annotations

from src.models.config import ApplicationConfig


class PlannerSettings:
    """Configures the planner service by wrapping ApplicationConfig settings."""

    def __init__(self, config: ApplicationConfig) -> None:
        self._config = config

    @property
    def enabled(self) -> bool:
        """Check if planner is enabled."""
        return self._config.planner_enabled

    @property
    def provider(self) -> str:
        """Get the configured LLM provider name."""
        return self._config.planner_provider

    @property
    def model(self) -> str:
        """Get the configured LLM model name."""
        return self._config.planner_model

    @property
    def temperature(self) -> float:
        """Get the configured model temperature."""
        return self._config.planner_temperature

    @property
    def max_tokens(self) -> int:
        """Get the configured maximum tokens to generate."""
        return self._config.planner_max_tokens

    @property
    def timeout(self) -> float:
        """Get the request timeout in seconds."""
        return self._config.planner_timeout

    @property
    def retry_count(self) -> int:
        """Get the request retry count."""
        return self._config.planner_retry_count

    @property
    def retry_delay(self) -> float:
        """Get the request retry delay in seconds."""
        return self._config.planner_retry_delay

    @property
    def raw_config(self) -> ApplicationConfig:
        """Access the underlying ApplicationConfig."""
        return self._config
