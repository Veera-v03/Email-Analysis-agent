"""Incident Repository implementation for processed email incidents."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.common.constants import Verdict
from src.database.models import Incident
from src.database.repositories.base import BaseRepository
from src.interfaces.repositories import IIncidentRepository


class IncidentRepository(BaseRepository[Incident, UUID], IIncidentRepository):
    """Repository handling Incident ORM operations."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Incident, session)

    async def list_by_tenant(
        self,
        tenant_id: UUID,
        verdict: Verdict | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Incident]:
        """List incident records for a tenant filtered by verdict and paginated."""
        stmt = select(Incident).where(
            Incident.tenant_id == tenant_id, Incident.is_deleted.is_(False)
        )
        if verdict:
            stmt = stmt.where(Incident.verdict == verdict.value)

        stmt = stmt.order_by(Incident.created_at.desc()).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update_status(
        self, incident_id: UUID, status: str, action_taken: str
    ) -> Incident | None:
        """Update incident status and action taken."""
        incident = await self.get_by_id(incident_id)
        if incident:
            incident.status = status
            incident.action_taken = action_taken
            await self.session.flush()
            await self.session.refresh(incident)
        return incident
