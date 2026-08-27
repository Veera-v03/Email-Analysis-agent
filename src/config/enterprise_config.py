"""Centralized Configuration Management with Environment Validation, Secrets Abstraction, and Feature Flags."""

from __future__ import annotations

import os
from typing import Any

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class EnterpriseSettings(BaseSettings):
    """Central configuration class validating env variables and secrets."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General Platform Settings
    platform_name: str = Field(default="ScamShield Enterprise Platform")
    environment: str = Field(default="production")  # development, staging, production
    secret_key: SecretStr | None = Field(default=None)
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=30)
    refresh_token_expire_days: int = Field(default=7)

    # Database Settings
    db_path: str = Field(default="data/enterprise.db")
    memory_dir: str = Field(default="data/memory")

    # Feature Flags
    enable_mfa: bool = Field(default=False)
    enable_multi_tenant: bool = Field(default=True)
    enable_realtime_notifications: bool = Field(default=True)
    enable_explainability_reports: bool = Field(default=True)

    # API Keys & Secrets Mock/Stubs (Central Secrets Abstraction)
    groq_api_key: SecretStr | None = Field(default=None)
    slack_webhook_url: str | None = Field(default=None)
    teams_webhook_url: str | None = Field(default=None)

    # Module 20 Notification & Alerting Configurations
    notification_rate_limit_per_minute: int = Field(default=60)
    notification_max_retries: int = Field(default=3)
    notification_retry_backoff_sec: float = Field(default=1.0)
    notification_timeout_sec: float = Field(default=5.0)
    notification_webhook_signing_secret: SecretStr | None = Field(default=None)
    smtp_host: str | None = Field(default=None)
    smtp_port: int = Field(default=587)
    smtp_user: str | None = Field(default=None)
    smtp_password: SecretStr | None = Field(default=None)
    smtp_from: str = Field(default="soc-alerts@scamshield.enterprise")
    smtp_use_tls: bool = Field(default=True)

    # Runtime overrides dictionary
    _overrides: dict[str, Any] = {}

    def get_secret(self, key: str, default: Any = None) -> Any:
        """Central secrets abstraction retrieving confidential configurations safely."""
        # Check runtime overrides first, then environment variables, then class fields
        if key in self._overrides:
            val = self._overrides[key]
            if isinstance(val, SecretStr):
                return val.get_secret_value()
            return val
        env_val = os.getenv(key)
        if env_val is not None:
            return env_val
        val = getattr(self, key.lower(), default)
        if isinstance(val, SecretStr):
            return val.get_secret_value()
        if (
            key.upper() == "SECRET_KEY"
            and val is None
            and self.environment == "development"
        ):
            return "super-secret-key-change-in-production-123456789"
        return val

    def set_override(self, key: str, value: Any) -> None:
        """Allow runtime configuration overrides (e.g. for unit testing)."""
        self._overrides[key] = value

    def is_feature_enabled(self, feature_name: str) -> bool:
        """Check if a feature flag is enabled."""
        override_key = f"ENABLE_{feature_name.upper()}"
        if override_key in self._overrides:
            return bool(self._overrides[override_key])

        # Check standard feature flag fields
        field_name = f"enable_{feature_name.lower()}"
        if hasattr(self, field_name):
            return bool(getattr(self, field_name))

        # Check environment variable
        env_val = os.getenv(override_key)
        if env_val is not None:
            return env_val.lower() in ("true", "1", "yes")

        return False


# Global central configuration instance
settings = EnterpriseSettings()
