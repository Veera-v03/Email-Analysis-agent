"""Comprehensive unit and integration test suite for Module 5 Email Ingestion Platform."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.container.di import Container
from src.database.base import Base
from src.database.models import EmailAccount, Tenant
from src.database.repositories.email_account_repository import EmailAccountRepository
from src.database.repositories.tenant_repository import TenantRepository
from src.events.base_event import BaseEvent
from src.events.ingestion_events import (
    EmailDownloadedEvent,
    EmailReceivedEvent,
    MailboxSyncCompletedEvent,
)
from src.ingestion.module import IngestionModule, register_ingestion_module
from src.ingestion.pipeline import IngestionPipeline
from src.ingestion.providers.gmail_provider import GmailProvider
from src.ingestion.providers.msgraph_provider import MicrosoftGraphProvider
from src.messaging.event_bus import InMemoryEventBus
from src.registry.module_registry import ModuleRegistry


def test_gmail_provider_unit() -> None:
    """Verify GmailProvider OAuth2, Watch API, sync, and EML fetch."""

    async def _run() -> None:
        provider = GmailProvider(access_token="test_access_token")
        assert provider.provider_name == "GMAIL"

        # 1. OAuth2 Authenticate & Refresh
        auth_res = await provider.authenticate()
        assert auth_res["access_token"] is not None

        refreshed = await provider.refresh_tokens("test_refresh_token")
        assert "refreshed" in refreshed["access_token"]

        # 2. Watch API
        watch_res = await provider.setup_watch("https://webhook.test")
        assert watch_res["historyId"] == "1000500"

        # 3. Initial & Incremental Sync
        summaries = await provider.fetch_initial_sync(limit=5)
        assert len(summaries) == 5

        inc_summaries = await provider.fetch_incremental_sync("1000500")
        assert len(inc_summaries) == 1

        # 4. Raw EML Fetch & Envelope Metadata
        raw_eml = await provider.get_raw_eml("msg_001")
        assert b"From: sender@example.com" in raw_eml

        meta = await provider.get_message_metadata("msg_001")
        assert meta["sender_address"] == "sender@example.com"

    asyncio.run(_run())


def test_msgraph_provider_scaffold() -> None:
    """Verify MicrosoftGraphProvider scaffold capabilities."""

    async def _run() -> None:
        provider = MicrosoftGraphProvider()
        assert provider.provider_name == "MS_GRAPH"

        auth_res = await provider.authenticate(auth_code="demo_auth_code")
        assert auth_res["access_token"] is not None

        summaries = await provider.fetch_initial_sync(limit=3)
        assert len(summaries) == 3

        raw_eml = await provider.get_raw_eml("msgraph_001")
        assert b"From: sender@microsoft.com" in raw_eml

    asyncio.run(_run())


def test_ingestion_pipeline_initial_sync() -> None:
    """Verify IngestionPipeline initial sync, database storage, and event publishing."""

    async def _run() -> None:
        published_events: list[BaseEvent] = []

        class MockPublisher:
            async def publish(self, event: BaseEvent) -> None:
                published_events.append(event)

        pipeline = IngestionPipeline(event_publisher=MockPublisher())

        # Setup SQLite Async Engine
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        async with session_factory() as session:
            tenant_repo = TenantRepository(session)
            account_repo = EmailAccountRepository(session)

            tenant = await tenant_repo.create(
                Tenant(org_name="Ingestion Test Org", domain_name="ingest.com")
            )
            account = await account_repo.create(
                EmailAccount(
                    tenant_id=tenant.id,
                    provider="GMAIL",
                    email_address="security@ingest.com",
                    access_token="test_access",
                    refresh_token="test_refresh",
                )
            )

            # Run Initial Sync
            count = await pipeline.run_initial_sync(session, account.id, limit=3)
            assert count == 3

            # Verify Events
            received_events = [
                e for e in published_events if isinstance(e, EmailReceivedEvent)
            ]
            downloaded_events = [
                e for e in published_events if isinstance(e, EmailDownloadedEvent)
            ]
            sync_events = [
                e for e in published_events if isinstance(e, MailboxSyncCompletedEvent)
            ]

            assert len(received_events) == 3
            assert len(downloaded_events) == 3
            assert len(sync_events) == 1
            assert sync_events[0].emails_processed == 3

        await engine.dispose()

    asyncio.run(_run())


def test_ingestion_module_lifecycle() -> None:
    """Verify IngestionModule DI registration and lifecycle hooks."""

    async def _run() -> None:
        di_c = Container()
        reg = ModuleRegistry()

        bus = InMemoryEventBus()
        ingestion_mod = register_ingestion_module(di_c, reg, event_publisher=bus)

        assert reg.get_module("ingestion") == ingestion_mod
        await reg.initialize_all()

        health = await reg.health_check_all()
        assert health.status == "UP"

        await reg.shutdown_all()

    asyncio.run(_run())
