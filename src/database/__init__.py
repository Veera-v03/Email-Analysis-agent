"""Database and persistence package for ScamON Enterprise."""

from __future__ import annotations

from src.database.base import (
    Base,
    SoftDeleteMixin,
    TenantIsolationMixin,
    TimestampMixin,
)
from src.database.engine import build_async_engine, get_database_url
from src.database.health import DatabaseHealthChecker
from src.database.models import Incident, Tenant, TenantPolicy, User
from src.database.module import DatabaseModule, register_database_module
from src.database.session import (
    build_async_session_factory,
    get_async_session,
    get_session_context,
    set_session_tenant_id,
)

__all__ = [
    "Base",
    "DatabaseHealthChecker",
    "DatabaseModule",
    "Incident",
    "SoftDeleteMixin",
    "Tenant",
    "TenantIsolationMixin",
    "TenantPolicy",
    "TimestampMixin",
    "User",
    "build_async_engine",
    "build_async_session_factory",
    "get_async_session",
    "get_database_url",
    "get_session_context",
    "register_database_module",
    "set_session_tenant_id",
]
