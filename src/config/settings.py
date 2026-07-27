"""Environment-backed configuration for the application."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.models.config import ApplicationConfig

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Load validated runtime settings from environment variables.

    Values defined in the process environment override values in the optional
    local `.env` file. Defaults support a safe local bootstrap.
    """

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Email Analysis Agent"
    version: str = "0.1.0"
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    groq_api_key: SecretStr | None = None
    data_directory: Path = PROJECT_ROOT / "data"

    @field_validator("debug", mode="before")
    @classmethod
    def normalize_debug_mode(cls, value: object) -> object:
        """Interpret common deployment-mode values as a disabled debug flag."""
        if isinstance(value, str) and value.lower() in {"release", "production"}:
            return False
        return value

    def to_application_config(self) -> ApplicationConfig:
        """Return a framework-independent, strict configuration contract."""
        return ApplicationConfig(
            app_name=self.app_name,
            version=self.version,
            debug=self.debug,
            log_level=self.log_level,
            data_directory=self.data_directory.resolve(),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Create and cache the process-wide settings instance."""
    return Settings()
