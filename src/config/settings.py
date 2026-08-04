"""Validated application settings management for ScamON Enterprise."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.common.constants import SystemEnvironment

if TYPE_CHECKING:
    from src.models.config import ApplicationConfig

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class ScamONSettings(BaseSettings):
    """Validated configuration settings loaded from env and Vault."""

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # General Platform Settings & Legacy Compatibility
    platform_name: str = Field(default="ScamON Enterprise Platform")
    app_name: str = Field(default="ScamON Enterprise Platform")
    version: str = Field(default="1.1.0")
    environment: SystemEnvironment = Field(default=SystemEnvironment.DEVELOPMENT)
    debug: bool = Field(default=False)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO"
    )
    log_format: Literal["json", "console"] = Field(default="json")
    data_directory: Path = Field(default=PROJECT_ROOT / "data")

    # Vault & Secret Path Configurations
    vault_enabled: bool = Field(default=False)
    vault_address: str | None = Field(default=None)
    vault_secret_path: str = Field(default="secret/data/scamon/production")
    secret_key: SecretStr | None = Field(default=None)
    groq_api_key: SecretStr | None = Field(default=None)

    # Authentication & Security Configurations
    jwt_algorithm: str = Field(default="RS256")
    access_token_expire_minutes: int = Field(default=15)
    refresh_token_expire_days: int = Field(default=7)

    # Database Connection Strings (Modular Monolith / Local Dev)
    postgres_url: SecretStr | None = Field(default=None)
    clickhouse_url: SecretStr | None = Field(default=None)
    neo4j_url: SecretStr | None = Field(default=None)
    redis_url: SecretStr | None = Field(default=None)
    s3_endpoint_url: str | None = Field(default=None)

    # Feature Flags (Matching SAS v1.1.0 Section 5.3)
    enable_llm_reasoning_engine: bool = Field(default=True)
    enable_dynamic_playwright_screenshots: bool = Field(default=True)
    enable_automated_clawback: bool = Field(default=True)
    enable_quishing_protection: bool = Field(default=True)
    enable_mfa: bool = Field(default=False)
    enable_multi_tenant: bool = Field(default=True)
    enable_audit_logging: bool = Field(default=True)

    # LLM & AI Governance Constraints (Matching SAS v1.1.0 Section 6)
    llm_primary_model: str = Field(default="llama-3.1-8b-instruct")
    llm_max_token_budget: int = Field(default=1200)
    llm_cost_budget_max_usd: float = Field(default=0.002)
    llm_borderline_score_min: int = Field(default=40)
    llm_borderline_score_max: int = Field(default=70)
    llm_pii_redaction_enabled: bool = Field(default=True)

    # Legacy Planner Settings (Backward Compatibility)
    planner_enabled: bool = Field(default=True)
    planner_provider: str = Field(default="groq")
    planner_model: str = Field(default="llama-3.1-8b-instruct")
    planner_temperature: float = Field(default=0.0)
    planner_max_tokens: int = Field(default=1024)
    planner_timeout: float = Field(default=30.0)
    planner_retry_count: int = Field(default=3)
    planner_retry_delay: float = Field(default=1.0)

    # Rate Limiting & Performance Constraints
    tenant_rate_limit_per_minute: int = Field(default=1000)
    max_attachment_decomposition_depth: int = Field(default=5)
    max_uncompressed_file_size_mb: int = Field(default=100)

    @field_validator("debug", mode="before")
    @classmethod
    def normalize_debug_mode(cls, value: object) -> object:
        """Interpret common deployment-mode values as a disabled debug flag."""
        if isinstance(value, str) and value.lower() in {"release", "production"}:
            return False
        return value

    def is_production(self) -> bool:
        """Check if executing in production environment."""
        return self.environment == SystemEnvironment.PRODUCTION

    def is_feature_enabled(self, feature_name: str) -> bool:
        """Check if a specific feature flag is enabled."""
        field_name = f"enable_{feature_name.lower()}"
        if hasattr(self, field_name):
            return bool(getattr(self, field_name))
        return False

    def to_application_config(self) -> ApplicationConfig:
        """Return a framework-independent, strict configuration contract."""
        from src.models.config import ApplicationConfig

        return ApplicationConfig(
            app_name=self.app_name,
            version=self.version,
            debug=self.debug,
            log_level=self.log_level,
            data_directory=self.data_directory.resolve(),
            planner_enabled=self.planner_enabled,
            planner_provider=self.planner_provider,
            planner_model=self.planner_model,
            planner_temperature=self.planner_temperature,
            planner_max_tokens=self.planner_max_tokens,
            planner_timeout=self.planner_timeout,
            planner_retry_count=self.planner_retry_count,
            planner_retry_delay=self.planner_retry_delay,
        )


# Backward compatibility alias
Settings = ScamONSettings


@lru_cache(maxsize=1)
def get_settings() -> ScamONSettings:
    """Create and cache process-wide validated settings instance."""
    return ScamONSettings()
