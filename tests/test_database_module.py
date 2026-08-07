"""Unit and integration test suite for Module 3 Database & Persistence Tier."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.common.constants import ActionTaken, Verdict
from src.container.di import Container
from src.database.base import Base
from src.database.engine import build_async_engine, get_database_url
from src.database.health import DatabaseHealthChecker
from src.database.models import Incident, Tenant, TenantPolicy, User
from src.database.module import register_database_module
from src.database.repositories.incident_repository import IncidentRepository
from src.database.repositories.tenant_policy_repository import TenantPolicyRepository
from src.database.repositories.tenant_repository import TenantRepository
from src.database.repositories.user_repository import UserRepository
from src.database.session import build_async_session_factory, set_session_tenant_id
from src.registry.module_registry import ModuleRegistry


def test_tenant_and_user_models() -> None:
    """Verify Tenant and User ORM model field mappings."""
    tenant_id = uuid4()
    tenant = Tenant(
        id=tenant_id,
        org_name="Enterprise Cyber Corp",
        domain_name="cybercorp.com",
        subscription_tier="ENTERPRISE",
        status="ACTIVE",
    )

    assert tenant.id == tenant_id
    assert tenant.domain_name == "cybercorp.com"

    user = User(
        tenant_id=tenant_id,
        email="cfo@cybercorp.com",
        display_name="Chief Financial Officer",
        role="ADMIN",
    )
    assert user.tenant_id == tenant_id
    assert user.role == "ADMIN"


def test_tenant_repository_crud() -> None:
    """Verify TenantRepository CRUD operations."""

    async def _run() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        async with session_factory() as session:
            repo = TenantRepository(session)

            tenant = Tenant(org_name="Acme Security", domain_name="acmesec.com")
            created = await repo.create(tenant)
            assert created.id is not None
            assert created.domain_name == "acmesec.com"

            fetched = await repo.get_by_domain("acmesec.com")
            assert fetched is not None
            assert fetched.id == created.id

            updated = await repo.update_status(created.id, "SUSPENDED")
            assert updated is not None
            assert updated.status == "SUSPENDED"

        await engine.dispose()

    asyncio.run(_run())


def test_user_repository_crud() -> None:
    """Verify UserRepository CRUD operations with tenant scope."""

    async def _run() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        async with session_factory() as session:
            tenant_repo = TenantRepository(session)
            user_repo = UserRepository(session)

            tenant = await tenant_repo.create(
                Tenant(org_name="Beta Org", domain_name="beta.com")
            )

            user1 = User(
                tenant_id=tenant.id, email="alice@beta.com", display_name="Alice User"
            )
            user2 = User(
                tenant_id=tenant.id, email="bob@beta.com", display_name="Bob User"
            )

            await user_repo.create(user1)
            await user_repo.create(user2)

            users = await user_repo.list_by_tenant(tenant.id)
            assert len(users) == 2

            by_email = await user_repo.get_by_email(tenant.id, "alice@beta.com")
            assert by_email is not None
            assert by_email.display_name == "Alice User"

        await engine.dispose()

    asyncio.run(_run())


def test_tenant_policy_repository() -> None:
    """Verify TenantPolicyRepository set_policy and get operations."""

    async def _run() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        async with session_factory() as session:
            policy_repo = TenantPolicyRepository(session)
            tenant_repo = TenantRepository(session)

            tenant = await tenant_repo.create(
                Tenant(org_name="Policy Org", domain_name="policy.com")
            )

            p1 = await policy_repo.set_policy(
                tenant.id, "CLAWBACK_THRESHOLD", "85", enabled=True
            )
            assert p1.policy_value == "85"

            p2 = await policy_repo.set_policy(
                tenant.id, "CLAWBACK_THRESHOLD", "90", enabled=True
            )
            assert p2.policy_value == "90"

            policies = await policy_repo.get_by_tenant_id(tenant.id)
            assert len(policies) == 1

        await engine.dispose()

    asyncio.run(_run())


def test_incident_repository() -> None:
    """Verify IncidentRepository operations."""

    async def _run() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        async with session_factory() as session:
            tenant_repo = TenantRepository(session)
            incident_repo = IncidentRepository(session)

            tenant = await tenant_repo.create(
                Tenant(org_name="Incident Org", domain_name="incidents.com")
            )

            inc1 = Incident(
                tenant_id=tenant.id,
                message_id="msg-1001",
                internet_message_id="<msg-1001@incidents.com>",
                sender_address="attacker@evil.com",
                recipient_address="victim@incidents.com",
                subject="Urgent wire transfer",
                risk_score=95,
                verdict=Verdict.MALICIOUS.value,
                action_taken=ActionTaken.RETRACTED.value,
                received_at=datetime.now(UTC),
            )

            created = await incident_repo.create(inc1)
            assert created.id is not None

            incidents = await incident_repo.list_by_tenant(
                tenant.id, verdict=Verdict.MALICIOUS
            )
            assert len(incidents) == 1
            assert incidents[0].message_id == "msg-1001"

        await engine.dispose()

    asyncio.run(_run())


def test_database_module_lifecycle() -> None:
    """Verify DatabaseModule DI registration and lifecycle hooks."""

    async def _run() -> None:
        di_c = Container()
        reg = ModuleRegistry()

        mod = register_database_module(
            di_c, reg, database_url="sqlite+aiosqlite:///:memory:"
        )

        assert reg.get_module("database") == mod
        await reg.initialize_all()

        health = await reg.health_check_all()
        assert health.status == "UP"

        await reg.shutdown_all()

    asyncio.run(_run())


def test_postgres_live_connection_and_rls() -> None:
    """Live integration test against PostgreSQL scamon database."""

    async def _run() -> None:
        pg_url = get_database_url()
        engine = build_async_engine(pg_url)
        session_factory = build_async_session_factory(engine)

        health_checker = DatabaseHealthChecker(engine)
        health = await health_checker.health_check()
        assert health.status == "HEALTHY"

        async with session_factory() as session:
            tenant_repo = TenantRepository(session)
            test_domain = f"test_{uuid4().hex[:8]}.com"
            tenant = await tenant_repo.create(
                Tenant(org_name="Live PG Test Org", domain_name=test_domain)
            )
            assert tenant.id is not None

            # Test RLS Session Setting
            await set_session_tenant_id(session, tenant.id)

            # Cleanup test tenant
            await tenant_repo.delete(tenant.id)
            await session.commit()

        await engine.dispose()

    asyncio.run(_run())
