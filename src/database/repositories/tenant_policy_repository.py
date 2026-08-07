"""Tenant Policy Repository implementation."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import TenantPolicy
from src.database.repositories.base import BaseRepository
from src.interfaces.repositories import ITenantPolicyRepository


class TenantPolicyRepository(
    BaseRepository[TenantPolicy, UUID], ITenantPolicyRepository
):
    """Repository handling TenantPolicy ORM operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(TenantPolicy, session)

    async def get_by_tenant_id(self, tenant_id: UUID) -> list[TenantPolicy]:
        """Fetch all active policy rules for a tenant."""
        stmt = select(TenantPolicy).where(TenantPolicy.tenant_id == tenant_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def set_policy(
        self, tenant_id: UUID, policy_name: str, policy_value: str, enabled: bool = True
    ) -> TenantPolicy:
        """Set or update policy rule value for a tenant."""
        stmt = select(TenantPolicy).where(
            TenantPolicy.tenant_id == tenant_id,
            TenantPolicy.policy_name == policy_name,
        )
        result = await self.session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            existing.policy_value = policy_value
            existing.enabled = enabled
            await self.session.flush()
            await self.session.refresh(existing)
            return existing

        new_policy = TenantPolicy(
            tenant_id=tenant_id,
            policy_name=policy_name,
            policy_value=policy_value,
            enabled=enabled,
        )
        self.session.add(new_policy)
        await self.session.flush()
        await self.session.refresh(new_policy)
        return new_policy
