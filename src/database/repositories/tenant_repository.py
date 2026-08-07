"""Tenant Repository implementation for ORM persistence."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import Tenant
from src.database.repositories.base import BaseRepository
from src.interfaces.repositories import ITenantRepository


class TenantRepository(BaseRepository[Tenant, UUID], ITenantRepository):
    """Repository handling Tenant ORM operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Tenant, session)

    async def get_by_domain(self, domain_name: str) -> Tenant | None:
        """Fetch tenant by unique domain name."""
        stmt = select(Tenant).where(Tenant.domain_name == domain_name.lower())
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_status(self, tenant_id: UUID, status: str) -> Tenant | None:
        """Update operational status of a tenant."""
        tenant = await self.get_by_id(tenant_id)
        if tenant:
            tenant.status = status
            await self.session.flush()
            await self.session.refresh(tenant)
        return tenant
