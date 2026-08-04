"""Common foundational primitives, constants, exceptions, and base DTOs."""

from __future__ import annotations

from src.common.constants import (
    ActionTaken,
    LogFormat,
    SystemEnvironment,
    ThreatCategory,
    Verdict,
)
from src.common.exceptions import (
    ConfigurationError,
    DependencyError,
    RateLimitExceededError,
    ResourceNotFoundError,
    ScamONError,
    SecurityViolationError,
    ServiceUnavailableError,
    ValidationError,
)
from src.common.models import (
    BaseDTO,
    BaseEventDTO,
    ComponentHealthDTO,
    ErrorDetailDTO,
    HealthStatusDTO,
)

__all__ = [
    "ActionTaken",
    "BaseDTO",
    "BaseEventDTO",
    "ComponentHealthDTO",
    "ConfigurationError",
    "DependencyError",
    "ErrorDetailDTO",
    "HealthStatusDTO",
    "LogFormat",
    "RateLimitExceededError",
    "ResourceNotFoundError",
    "ScamONError",
    "SecurityViolationError",
    "ServiceUnavailableError",
    "SystemEnvironment",
    "ThreatCategory",
    "ValidationError",
    "Verdict",
]
