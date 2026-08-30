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
from src.common.redis_client import (
    AsyncRedisClient,
    DistributedRateLimiter,
    DistributedTenantLock,
    InMemoryRedisClient,
    ThreatIntelRedisCache,
    get_redis_client,
    set_redis_client,
)

__all__ = [
    "ActionTaken",
    "AsyncRedisClient",
    "BaseDTO",
    "BaseEventDTO",
    "ComponentHealthDTO",
    "ConfigurationError",
    "DependencyError",
    "DistributedRateLimiter",
    "DistributedTenantLock",
    "ErrorDetailDTO",
    "HealthStatusDTO",
    "InMemoryRedisClient",
    "LogFormat",
    "RateLimitExceededError",
    "ResourceNotFoundError",
    "ScamONError",
    "SecurityViolationError",
    "ServiceUnavailableError",
    "SystemEnvironment",
    "ThreatCategory",
    "ThreatIntelRedisCache",
    "ValidationError",
    "Verdict",
    "get_redis_client",
    "set_redis_client",
]
