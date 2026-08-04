"""Application Bootstrap Initializer for ScamON Enterprise Platform Foundation."""

from __future__ import annotations

from src.config.logging import get_logger, setup_logging
from src.config.settings import ScamONSettings, get_settings
from src.container.di import Container, container
from src.registry.module_registry import ModuleRegistry, registry

logger = get_logger("scamon.bootstrap")


def bootstrap_application() -> Container:
    """Bootstrap platform foundation services, logging, and settings.

    Returns:
        Configured Dependency Injection Container instance.
    """
    # 1. Initialize logging system
    setup_logging()

    # 2. Load validated system settings
    settings: ScamONSettings = get_settings()

    # 3. Ensure base data storage directory exists
    settings.data_directory.mkdir(parents=True, exist_ok=True)

    # 4. Register foundational platform instances in Dependency Injection container
    container.register_instance(ScamONSettings, settings)
    container.register_instance(ModuleRegistry, registry)

    logger.info(
        "Bootstrapped %s v%s [Environment: %s, Log Level: %s, Vault: %s]",
        settings.platform_name,
        settings.version,
        settings.environment.value,
        settings.log_level,
        "ENABLED" if settings.vault_enabled else "DISABLED",
    )

    return container
