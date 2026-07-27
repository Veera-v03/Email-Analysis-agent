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
