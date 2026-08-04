"""Thread-safe Module Lifecycle Registry for ScamON Enterprise."""

from __future__ import annotations

import asyncio
import time

from src.common.constants import SystemEnvironment
from src.common.exceptions import ModuleLifecycleError
from src.common.models import ComponentHealthDTO, HealthStatusDTO
from src.config.logging import get_logger
from src.config.settings import get_settings
from src.interfaces.base import IModule

logger = get_logger("scamon.registry")


class ModuleRegistry:
    """Thread-safe lifecycle manager for registered modular services."""

    def __init__(self) -> None:
        self._modules: dict[str, IModule] = {}
        self._initialized: bool = False
        self._lock = asyncio.Lock()

    def register(self, module: IModule) -> None:
        """Register a modular service with the platform lifecycle registry."""
        if module.name in self._modules:
            raise ModuleLifecycleError(
                message=f"Module '{module.name}' is already registered.",
                details={"module_name": module.name},
            )
        self._modules[module.name] = module
        logger.info("Registered module '%s' (v%s)", module.name, module.version)

    def get_module(self, name: str) -> IModule:
        """Retrieve a registered module instance by name."""
        if name not in self._modules:
            raise ModuleLifecycleError(
                message=f"Module '{name}' is not registered.",
                details={"requested_module": name},
            )
        return self._modules[name]

    def list_modules(self) -> list[IModule]:
        """Return a list of all registered modules."""
        return list(self._modules.values())

    async def initialize_all(self) -> None:
        """Sequential initialization of all registered platform modules."""
        async with self._lock:
            if self._initialized:
                logger.warning("Module registry is already initialized.")
                return

            logger.info("Initializing %d registered modules...", len(self._modules))
            for name, module in self._modules.items():
                start_time = time.perf_counter()
                try:
                    logger.info("Initializing module '%s'...", name)
                    await module.initialize()
                    elapsed_ms = (time.perf_counter() - start_time) * 1000
                    logger.info(
                        "Initialized module '%s' successfully in %.2fms",
                        name,
                        elapsed_ms,
                    )
                except Exception as exc:
                    logger.error("Failed to initialize module '%s': %s", name, exc)
                    raise ModuleLifecycleError(
                        message=f"Failed to initialize module '{name}': {exc}",
                        details={"module_name": name, "error": str(exc)},
                    ) from exc

            self._initialized = True
            logger.info("All modules initialized successfully.")

    async def shutdown_all(self) -> None:
        """Orderly shutdown of all registered modules in reverse registration order."""
        async with self._lock:
            if not self._initialized:
                logger.warning("Module registry is not initialized.")
                return

            logger.info("Shutting down modules...")
            # Shutdown in reverse order of registration
            for name, module in reversed(list(self._modules.items())):
                try:
                    logger.info("Shutting down module '%s'...", name)
                    await module.shutdown()
                    logger.info("Module '%s' shut down successfully.", name)
                except Exception as exc:
                    logger.error("Error during shutdown of module '%s': %s", name, exc)

            self._initialized = False
            logger.info("All modules shut down successfully.")

    async def health_check_all(self) -> HealthStatusDTO:
        """Execute health check across all registered modules and aggregate report."""
        component_reports: list[ComponentHealthDTO] = []
        overall_healthy: bool = True

        for name, module in self._modules.items():
            start_time = time.perf_counter()
            try:
                report = await module.health_check()
                component_reports.append(report)
                if report.status != "HEALTHY":
                    overall_healthy = False
            except Exception as exc:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                logger.error("Health check failed for module '%s': %s", name, exc)
                component_reports.append(
                    ComponentHealthDTO(
                        component_name=name,
                        status="UNHEALTHY",
                        latency_ms=elapsed_ms,
                        details={"error": str(exc)},
                    )
                )
                overall_healthy = False

        env: SystemEnvironment = get_settings().environment
        status_str: str = "UP" if overall_healthy else "DEGRADED"

        return HealthStatusDTO(
            status=status_str,
            environment=env.value,
            components=component_reports,
        )


# Global central module registry instance
registry = ModuleRegistry()
