"""Repository interface protocols for ScamON Enterprise database access."""

from __future__ import annotations

from typing import Any, Protocol, TypeVar, runtime_checkable
from uuid import UUID

from src.common.constants import Verdict

T = TypeVar("T")
ID = TypeVar("ID")


@runtime_checkable
class IBaseRepository[T, ID](Protocol):
    """Generic base repository interface protocol."""

    async def get_by_id(self, entity_id: ID) -> T | None:
        """Fetch entity by primary key ID."""
        ...

    async def list_all(self, limit: int = 100, offset: int = 0) -> list[T]:
        """List entities with pagination."""
        ...

    async def create(self, entity: T) -> T:
        """Persist new entity."""
        ...

    async def update(self, entity: T) -> T:
        """Update existing entity."""
        ...

    async def delete(self, entity_id: ID) -> bool:
        """Delete entity by ID."""
        ...

    async def count(self) -> int:
        """Return total entity count."""
        ...


@runtime_checkable
class ITenantRepository(Protocol):
    """Repository interface for Tenant entity operations."""

    async def get_by_id(self, tenant_id: UUID) -> Any | None:
        """Fetch tenant by UUID primary key."""
        ...

    async def get_by_domain(self, domain_name: str) -> Any | None:
        """Fetch tenant by unique domain name."""
        ...

    async def create(self, tenant: Any) -> Any:
        """Persist new tenant."""
        ...

    async def update_status(self, tenant_id: UUID, status: str) -> Any | None:
        """Update tenant operational status."""
        ...


@runtime_checkable
class IUserRepository(Protocol):
    """Repository interface for User entity operations."""

    async def get_by_id(self, user_id: UUID) -> Any | None:
        """Fetch user by UUID."""
        ...

    async def get_by_email(self, tenant_id: UUID, email: str) -> Any | None:
        """Fetch user by email within a tenant."""
        ...

    async def list_by_tenant(
        self, tenant_id: UUID, limit: int = 100, offset: int = 0
    ) -> list[Any]:
        """List users belonging to a specific tenant."""
        ...

    async def create(self, user: Any) -> Any:
        """Persist new user."""
        ...


@runtime_checkable
class ITenantPolicyRepository(Protocol):
    """Repository interface for TenantPolicy entity operations."""

    async def get_by_tenant_id(self, tenant_id: UUID) -> Any | None:
        """Fetch active policy configuration for a tenant."""
        ...

    async def set_policy(
        self, tenant_id: UUID, policy_name: str, policy_value: str, enabled: bool = True
    ) -> Any:
        """Set or update policy rule value for a tenant."""
        ...


@runtime_checkable
class IIncidentRepository(Protocol):
    """Repository interface for Incident entity operations."""

    async def get_by_id(self, incident_id: UUID) -> Any | None:
        """Fetch incident record by UUID."""
        ...

    async def list_by_tenant(
        self,
        tenant_id: UUID,
        verdict: Verdict | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Any]:
        """List incident records for a tenant filtered by verdict and paginated."""
        ...

    async def create(self, incident: Any) -> Any:
        """Persist new incident record."""
        ...

    async def update_status(
        self, incident_id: UUID, status: str, action_taken: str
    ) -> Any | None:
        """Update incident remediation status and action taken."""
        ...
