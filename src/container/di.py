"""Thread-safe Dependency Injection Container for ScamON Enterprise."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any, TypeVar

from src.common.exceptions import DependencyError

T = TypeVar("T")


class Container:
    """Thread-safe, lightweight Dependency Injection container."""

    def __init__(self) -> None:
        self._instances: dict[type[Any], Any] = {}
        self._factories: dict[type[Any], tuple[Callable[[], Any], bool]] = {}
        self._lock = threading.RLock()

    def register_instance(self, interface_type: type[T], instance: T) -> None:
        """Register a pre-constructed singleton instance for an interface type."""
        with self._lock:
            self._instances[interface_type] = instance

    def register_factory(
        self,
        interface_type: type[T],
        factory: Callable[[], T],
        singleton: bool = True,
    ) -> None:
        """Register a factory function for producing interface instances."""
        with self._lock:
            self._factories[interface_type] = (factory, singleton)

    def resolve(self, interface_type: type[T]) -> T:
        """Resolve and return an instance bound to the requested interface type."""
        with self._lock:
            # Return existing singleton instance if registered
            if interface_type in self._instances:
                instance = self._instances[interface_type]
                assert isinstance(instance, interface_type)
                return instance

            # Check if factory is registered
            if interface_type in self._factories:
                factory, singleton = self._factories[interface_type]
                created_instance = factory()

                if singleton:
                    self._instances[interface_type] = created_instance

                assert isinstance(created_instance, interface_type)
                return created_instance

            name = interface_type.__name__
            raise DependencyError(
                message=f"No dependency provider registered for interface: {name}",
                details={"interface": name},
            )

    def has(self, interface_type: type[Any]) -> bool:
        """Check if an interface type is registered in the container."""
        with self._lock:
            return (
                interface_type in self._instances or interface_type in self._factories
            )

    def reset(self) -> None:
        """Clear registered instances and factories (used in tests)."""
        with self._lock:
            self._instances.clear()
            self._factories.clear()


# Global central dependency injection container instance
container = Container()
