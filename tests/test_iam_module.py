"""Comprehensive unit and integration test suite for Module 4 Identity & Access Management (IAM)."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.container.di import Container
from src.database.base import Base
from src.database.models import Tenant, User
from src.database.repositories.tenant_repository import TenantRepository
from src.database.repositories.user_repository import UserRepository
from src.events.base_event import BaseEvent
from src.events.iam_events import (
    PermissionDeniedEvent,
    TokenRefreshedEvent,
    UserLoggedInEvent,
    UserLoggedOutEvent,
    UserLoginFailedEvent,
)
from src.messaging.event_bus import InMemoryEventBus
from src.registry.module_registry import ModuleRegistry
from src.security.auth_service import AuthenticationService
from src.security.exceptions import (
    AuthenticationError,
    AuthorizationError,
    InvalidTokenError,
    TokenExpiredError,
)
from src.security.keys import RSAKeyManager
from src.security.models import (
    AuthenticatedUser,
    Permission,
    Role,
)
from src.security.module import IAMModule, register_iam_module
from src.security.password import PasswordHasher
from src.security.rbac import AuthorizationService
from src.security.token_manager import TokenManager


def test_rsa_key_manager() -> None:
    """Verify RSA 2048-bit key pair generation."""
    km = RSAKeyManager()
    assert "-----BEGIN PRIVATE KEY-----" in km.private_key_pem
    assert "-----BEGIN PUBLIC KEY-----" in km.public_key_pem


def test_password_hasher() -> None:
    """Verify password hashing and verification."""
    pwd = "SecretPassword123!"
    hashed = PasswordHasher.hash_password(pwd)
    assert hashed.startswith("pbkdf2_sha256$")
    assert PasswordHasher.verify_password(pwd, hashed) is True
    assert PasswordHasher.verify_password("WrongPassword", hashed) is False


def test_token_manager_rs256() -> None:
    """Verify RS256 token creation, claims decoding, and revocation."""
    km = RSAKeyManager()
    tm = TokenManager(key_manager=km, access_token_expire_minutes=5)

    user_id = uuid4()
    tenant_id = uuid4()

    token_pair = tm.create_token_pair(
        user_id=user_id,
        tenant_id=tenant_id,
        email="analyst@enterprise.com",
        role=Role.ANALYST,
    )

    assert token_pair.access_token is not None
    assert token_pair.refresh_token is not None

    # Decode Access Token
    payload = tm.decode_token(token_pair.access_token, expected_type="access")
    assert payload.sub == user_id
    assert payload.tenant_id == tenant_id
    assert payload.email == "analyst@enterprise.com"
    assert payload.role == Role.ANALYST

    # Revoke Token
    tm.revoke_token(payload.jti)
    with pytest.raises(InvalidTokenError):
        tm.decode_token(token_pair.access_token, expected_type="access")


def test_auth_service_and_events() -> None:
    """Verify AuthenticationService login, refresh, logout, and event publishing."""

    async def _run() -> None:
        published_events: list[BaseEvent] = []

        # Create Mock Event Publisher
        class MockPublisher:
            async def publish(self, event: BaseEvent) -> None:
                published_events.append(event)

        publisher = MockPublisher()
        km = RSAKeyManager()
        tm = TokenManager(key_manager=km)
        auth_service = AuthenticationService(
            token_manager=tm, event_publisher=publisher
        )

        # Setup SQLite Async Session
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
                Tenant(org_name="IAM Test Org", domain_name="iam.com")
            )
            hashed_pwd = PasswordHasher.hash_password("MySecurePass1!")
            user = await user_repo.create(
                User(
                    tenant_id=tenant.id,
                    email="secops@iam.com",
                    display_name="SecOps Analyst",
                    role="ANALYST",
                )
            )
            # Attach password_hash attribute for test user
            setattr(user, "password_hash", hashed_pwd)

            # 1. Successful Authentication
            auth_user, tokens = await auth_service.authenticate_credentials(
                session=session,
                email="secops@iam.com",
                password="MySecurePass1!",
                tenant_domain="iam.com",
            )

            assert auth_user.user_id == user.id
            assert auth_user.role == Role.ANALYST
            assert Permission.READ_INCIDENT.value in auth_user.permissions

            # Check UserLoggedInEvent
            assert len(published_events) == 1
            assert isinstance(published_events[0], UserLoggedInEvent)
            assert published_events[0].email == "secops@iam.com"

            # 2. Refresh Token Rotation
            new_tokens = await auth_service.refresh_session(tokens.refresh_token)
            assert new_tokens.access_token != tokens.access_token
            assert isinstance(published_events[-1], TokenRefreshedEvent)

            # 3. Failed Authentication
            with pytest.raises(AuthenticationError):
                await auth_service.authenticate_credentials(
                    session=session,
                    email="secops@iam.com",
                    password="WrongPassword!",
                    tenant_domain="iam.com",
                )
            assert isinstance(published_events[-1], UserLoginFailedEvent)

            # 4. Logout User
            await auth_service.logout(new_tokens.access_token)
            assert isinstance(published_events[-1], UserLoggedOutEvent)

        await engine.dispose()

    asyncio.run(_run())


def test_authorization_service_and_rbac() -> None:
    """Verify AuthorizationService permission checks, role checks, and tenant isolation."""

    async def _run() -> None:
        published_events: list[BaseEvent] = []

        class MockPublisher:
            async def publish(self, event: BaseEvent) -> None:
                published_events.append(event)

        rbac = AuthorizationService(event_publisher=MockPublisher())

        analyst = AuthenticatedUser(
            user_id=uuid4(),
            tenant_id=uuid4(),
            email="analyst@test.com",
            display_name="Analyst",
            role=Role.ANALYST,
            permissions=[
                Permission.READ_INCIDENT.value,
                Permission.REMEDIATE_INCIDENT.value,
            ],
        )

        # 1. Authorize Valid Permission
        await rbac.authorize_permission(analyst, Permission.READ_INCIDENT)

        # 2. Permission Denied
        with pytest.raises(AuthorizationError):
            await rbac.authorize_permission(analyst, Permission.MANAGE_USERS)
        assert len(published_events) == 1
        assert isinstance(published_events[0], PermissionDeniedEvent)

        # 3. Authorize Role
        rbac.authorize_role(analyst, [Role.ANALYST, Role.ADMIN])
        with pytest.raises(AuthorizationError):
            rbac.authorize_role(analyst, [Role.SUPER_ADMIN])

        # 4. Tenant Isolation Verification
        rbac.verify_tenant_isolation(analyst, analyst.tenant_id)
        with pytest.raises(AuthorizationError):
            rbac.verify_tenant_isolation(analyst, uuid4())

    asyncio.run(_run())


def test_iam_module_lifecycle() -> None:
    """Verify IAMModule initialization, health check, and DI container integration."""

    async def _run() -> None:
        di_c = Container()
        reg = ModuleRegistry()

        bus = InMemoryEventBus()
        iam_mod = register_iam_module(di_c, reg, event_publisher=bus)

        assert reg.get_module("iam") == iam_mod
        await reg.initialize_all()

        health = await reg.health_check_all()
        assert health.status == "UP"

        await reg.shutdown_all()

    asyncio.run(_run())
