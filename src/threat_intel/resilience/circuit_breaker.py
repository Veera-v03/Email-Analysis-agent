"""Provider Rate Limiter and Circuit Breaker for resilience and fault tolerance."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from enum import StrEnum

from src.config.logging import get_logger
from src.threat_intel.exceptions import CircuitBreakerOpenError

logger = get_logger("scamon.threat_intel.resilience")


class CircuitState(StrEnum):
    """Circuit breaker operational state."""

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class ProviderCircuitBreaker:
    """Stateful circuit breaker preventing cascading failures to external APIs."""

    def __init__(
        self,
        provider_name: str,
        failure_threshold: int = 3,
        recovery_timeout_seconds: float = 30.0,
    ) -> None:
        self.provider_name = provider_name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout_seconds
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_state_change = time.monotonic()

    def allow_request(self) -> bool:
        """Check if request is permitted under current circuit state."""
        now = time.monotonic()

        if self.state == CircuitState.OPEN:
            if now - self.last_state_change >= self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                self.last_state_change = now
                logger.info(
                    "[%s] Circuit state transitioned to HALF_OPEN", self.provider_name
                )
                return True
            return False

        return True

    def record_success(self) -> None:
        """Record successful lookup and reset failure count."""
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.CLOSED
            self.last_state_change = time.monotonic()
            logger.info("[%s] Circuit state restored to CLOSED", self.provider_name)

        self.failure_count = 0

    def record_failure(self) -> None:
        """Record failed lookup and trip breaker if threshold is exceeded."""
        self.failure_count += 1
        if (
            self.failure_count >= self.failure_threshold
            and self.state != CircuitState.OPEN
        ):
            self.state = CircuitState.OPEN
            self.last_state_change = time.monotonic()
            logger.warning(
                "[%s] Circuit breaker TRIPPED to OPEN after %d failures",
                self.provider_name,
                self.failure_count,
            )


class ProviderRateLimiter:
    """Token bucket or sliding window rate limiter for provider query throttling."""

    def __init__(self, max_queries_per_minute: int = 60) -> None:
        self.max_queries = max_queries_per_minute
        self.tokens = float(max_queries_per_minute)
        self.last_refill = time.monotonic()

    def acquire(self) -> bool:
        """Acquire a token for API lookup."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(
            float(self.max_queries), self.tokens + elapsed * (self.max_queries / 60.0)
        )
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False
