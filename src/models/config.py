"""Configuration data contracts."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr


class ApplicationConfig(BaseModel):
    """Validated configuration consumed by application components."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    app_name: StrictStr = Field(min_length=1, max_length=100)
    version: StrictStr = Field(min_length=1, max_length=50)
    debug: StrictBool
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    data_directory: Path
    planner_enabled: StrictBool
    planner_provider: StrictStr
    planner_model: StrictStr
    planner_temperature: float
    planner_max_tokens: int
    planner_timeout: float
    planner_retry_count: int
    planner_retry_delay: float
