"""Abstract Interface contracts for microservices and platform components."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from src.common.models import ComponentHealthDTO
from src.config.settings import ScamONSettings


@runtime_checkable
class IServiceContract(Protocol):
    """Marker interface protocol for all domain services."""

    pass


@runtime_checkable
class IHealthCheckable(Protocol):
    """Protocol for components supporting health status reporting."""

    async def health_check(self) -> ComponentHealthDTO:
        """Perform a component health check and return detailed status."""
        ...


@runtime_checkable
class IConfigurable(Protocol):
    """Protocol for components accepting dynamic configuration settings."""

    def configure(self, settings: ScamONSettings) -> None:
        """Apply system settings to component instance."""
        ...


class IModule(ABC):
    """Abstract Base Class for all ScamON Enterprise modular services."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique module name identifier."""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Module semver version string."""
        ...

    @abstractmethod
    async def initialize(self) -> None:
        """Lifecycle hook: Initialize module dependencies and resources."""
        ...

    @abstractmethod
    async def shutdown(self) -> None:
        """Lifecycle hook: Orderly shutdown of module resources."""
        ...

    @abstractmethod
    async def health_check(self) -> ComponentHealthDTO:
        """Lifecycle hook: Evaluate and return module health status."""
        ...
