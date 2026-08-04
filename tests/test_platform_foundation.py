"""Unit tests for ScamON Enterprise Platform Foundation (Sprint 1.1 Module 1)."""

from __future__ import annotations

import asyncio

import pytest

from src.bootstrap import bootstrap_application
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
    ModuleLifecycleError,
    ScamONError,
    ValidationError,
)
from src.common.models import BaseDTO, ComponentHealthDTO, HealthStatusDTO
from src.config.logging import clear_log_context, set_log_context, setup_logging
from src.config.settings import ScamONSettings, get_settings
from src.container.di import Container
from src.interfaces.base import IModule
from src.registry.module_registry import ModuleRegistry


class MockModule(IModule):
    """Mock module for testing lifecycle registry operations."""

    def __init__(self, name: str = "mock_service", version: str = "1.0.0") -> None:
        self._name = name
        self._version = version
        self.initialized = False
        self.shut_down = False

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return self._version

    async def initialize(self) -> None:
        self.initialized = True

    async def shutdown(self) -> None:
        self.shut_down = True

    async def health_check(self) -> ComponentHealthDTO:
        return ComponentHealthDTO(
            component_name=self._name,
            status="HEALTHY",
            latency_ms=1.5,
            details={"mock": True},
        )


def test_constants_and_enums() -> None:
    """Verify system constants and enumeration values."""
    assert SystemEnvironment.PRODUCTION == "production"
    assert Verdict.MALICIOUS == "MALICIOUS"
    assert ThreatCategory.QUISHING == "QUISHING"
    assert ActionTaken.RETRACTED == "RETRACTED"
    assert LogFormat.JSON == "json"


def test_exception_hierarchy() -> None:
    """Verify custom exception serialization and status codes."""
    err = ValidationError("Invalid payload", details={"field": "email"})
    assert err.status_code == 400
    assert err.error_code == "ERR_VALIDATION_FAILED"

    dict_repr = err.to_dict()
    assert "error" in dict_repr
    assert dict_repr["error"]["code"] == "ERR_VALIDATION_FAILED"
    assert dict_repr["error"]["details"]["field"] == "email"

    cfg_err = ConfigurationError("Vault unreachable")
    assert cfg_err.status_code == 500
    assert isinstance(cfg_err, ScamONError)


def test_dto_base_models() -> None:
    """Verify DTO immutability and serialization."""

    class SampleDTO(BaseDTO):
        name: str
        val: int

    dto = SampleDTO(name="test", val=42)
    assert dto.name == "test"

    with pytest.raises(Exception):
        # Immutability check (frozen)
        dto.name = "changed"  # type: ignore[misc]


def test_dependency_injection_container() -> None:
    """Verify thread-safe DI container singleton and factory resolution."""
    c = Container()

    # Instance registration
    settings = get_settings()
    c.register_instance(ScamONSettings, settings)
    assert c.has(ScamONSettings)
    assert c.resolve(ScamONSettings) == settings

    # Factory registration
    class DynamicService:
        pass

    c.register_factory(DynamicService, lambda: DynamicService(), singleton=True)
    inst1 = c.resolve(DynamicService)
    inst2 = c.resolve(DynamicService)
    assert inst1 is inst2

    # Unregistered dependency
    class Unregistered:
        pass

    with pytest.raises(DependencyError):
        c.resolve(Unregistered)


def test_module_registry_lifecycle() -> None:
    """Verify registration, initialization, health checks, and shutdown of modules."""

    async def _run() -> None:
        reg = ModuleRegistry()
        module1 = MockModule("module_1")
        module2 = MockModule("module_2")

        reg.register(module1)
        reg.register(module2)

        assert len(reg.list_modules()) == 2
        assert reg.get_module("module_1") == module1

        # Duplicate registration error
        with pytest.raises(ModuleLifecycleError):
            reg.register(module1)

        # Initialize all
        await reg.initialize_all()
        assert module1.initialized is True
        assert module2.initialized is True

        # Health checks aggregation
        health: HealthStatusDTO = await reg.health_check_all()
        assert health.status == "UP"
        assert len(health.components) == 2

        # Shutdown all
        await reg.shutdown_all()
        assert module1.shut_down is True
        assert module2.shut_down is True

    asyncio.run(_run())


def test_bootstrap_application() -> None:
    """Verify application bootstrap process."""
    c = bootstrap_application()
    assert c.has(ScamONSettings)
    assert c.has(ModuleRegistry)


def test_logging_context() -> None:
    """Verify logging setup and trace context management."""
    setup_logging()
    set_log_context(trace_id="trace-12345", tenant_id="tenant-67890")
    clear_log_context()
