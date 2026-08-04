"""Interface contracts and abstractions for ScamON Enterprise."""

from __future__ import annotations

from src.interfaces.base import (
    IConfigurable,
    IHealthCheckable,
    IModule,
    IServiceContract,
)

__all__ = [
    "IConfigurable",
    "IHealthCheckable",
    "IModule",
    "IServiceContract",
]
