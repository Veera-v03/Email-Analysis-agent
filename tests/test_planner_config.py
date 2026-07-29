"""Unit tests for planner configuration settings."""

from __future__ import annotations

import os
from unittest import mock

from src.config.settings import Settings
from src.planner.configuration.settings import PlannerSettings


def test_settings_load_defaults() -> None:
    """Verify that global settings capture new configuration properties."""
    settings = Settings()
    assert settings.planner_enabled is True
    assert settings.planner_provider == "groq"
    assert settings.planner_model == "llama-3.1-8b-instant"
    assert settings.planner_temperature == 0.0
    assert settings.planner_max_tokens == 1024
    assert settings.planner_timeout == 30.0
    assert settings.planner_retry_count == 3
    assert settings.planner_retry_delay == 1.0


def test_settings_override_via_env() -> None:
    """Verify that process environment variables successfully override settings."""
    env_overrides = {
        "PLANNER_ENABLED": "False",
        "PLANNER_PROVIDER": "custom_provider",
        "PLANNER_MODEL": "test-model",
        "PLANNER_TEMPERATURE": "0.7",
        "PLANNER_MAX_TOKENS": "512",
        "PLANNER_TIMEOUT": "15.0",
        "PLANNER_RETRY_COUNT": "5",
        "PLANNER_RETRY_DELAY": "2.5",
    }
    with mock.patch.dict(os.environ, env_overrides):
        # Settings names mapped case-insensitively by pydantic-settings
        settings = Settings()
        assert settings.planner_enabled is False
        assert settings.planner_provider == "custom_provider"
        assert settings.planner_model == "test-model"
        assert settings.planner_temperature == 0.7
        assert settings.planner_max_tokens == 512
        assert settings.planner_timeout == 15.0
        assert settings.planner_retry_count == 5
        assert settings.planner_retry_delay == 2.5


def test_planner_settings_wrapper() -> None:
    """Verify that PlannerSettings extracts property values correctly from ApplicationConfig."""
    settings = Settings()
    config = settings.to_application_config()
    planner_settings = PlannerSettings(config)

    assert planner_settings.enabled is True
    assert planner_settings.provider == "groq"
    assert planner_settings.model == "llama-3.1-8b-instant"
    assert planner_settings.temperature == 0.0
    assert planner_settings.max_tokens == 1024
    assert planner_settings.timeout == 30.0
    assert planner_settings.retry_count == 3
    assert planner_settings.retry_delay == 1.0
    assert planner_settings.raw_config == config
