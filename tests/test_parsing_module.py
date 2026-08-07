"""Comprehensive unit and integration test suite for Module 6 MIME Parsing & Decomposition Engine."""

from __future__ import annotations

import asyncio
from uuid import uuid4

from src.container.di import Container
from src.events.base_event import BaseEvent
from src.events.parsing_events import AttachmentExtractedEvent, EmailParsedEvent
from src.messaging.event_bus import InMemoryEventBus
from src.parsing.engine import MimeParserEngine
from src.parsing.headers.header_parser import (
    decode_rfc2047_header,
    parse_address_header,
)
from src.parsing.module import ParsingModule, register_parsing_module
from src.parsing.pipeline import ParsingPipeline
from src.parsing.url.url_extractor import extract_urls_from_html, extract_urls_from_text
from src.registry.module_registry import ModuleRegistry


def test_header_parser_rfc2047_decoding() -> None:
    """Verify RFC 2047 header decoding and address parsing."""
    assert decode_rfc2047_header("=?utf-8?B?VXI=parse?=") is not None
    decoded = decode_rfc2047_header("=?utf-8?Q?Security_Alert?=")
    assert decoded == "Security Alert"

    addr = parse_address_header("John Doe <john.doe@enterprise.com>")
    assert addr.name == "John Doe"
    assert addr.address == "john.doe@enterprise.com"


def test_url_extractor_mismatch_detection() -> None:
    """Verify URL extraction and link display text mismatch flag."""
    html = '<a href="https://evil-phish.ru/login">https://paypal.com/verify</a>'
    dtos = extract_urls_from_html(html)
    assert len(dtos) == 1
    assert dtos[0].url == "https://evil-phish.ru/login"
    assert dtos[0].is_mismatched is True

    text_urls = extract_urls_from_text("Check https://bit.ly/3xX9a for details")
    assert len(text_urls) == 1
    assert text_urls[0].is_shortened is True


def test_parsing_pipeline_full_mime() -> None:
    """Verify full 8-stage parsing pipeline on multipart MIME email with attachment and zero-width chars."""
    raw_eml = (
        b"From: =?utf-8?Q?Security_Team?= <security@company.com>\r\n"
        b"To: analyst@company.com\r\n"
        b"Subject: Urgent Action Required\r\n"
        b"Message-ID: <msg_999@company.com>\r\n"
        b"Date: Fri, 07 Aug 2026 10:00:00 +0000\r\n"
        b"Received: from mail.company.com ([192.168.1.50]) by mx.company.com; Fri, 07 Aug 2026 10:00:00 +0000\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="BOUNDARY123"\r\n\r\n'
        b"--BOUNDARY123\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Dear user,\xe2\x80\x8b please click https://login.secure.com to verify.\r\n\r\n"
        b"--BOUNDARY123\r\n"
        b'Content-Type: image/png; name="logo.png"\r\n'
        b"Content-Transfer-Encoding: base64\r\n"
        b'Content-Disposition: attachment; filename="logo.png"\r\n\r\n'
        b"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==\r\n"
        b"--BOUNDARY123--"
    )

    pipeline = ParsingPipeline()
    raw_id = uuid4()
    acc_id = uuid4()
    ten_id = uuid4()

    parsed = pipeline.parse(
        raw_eml_bytes=raw_eml,
        raw_email_id=raw_id,
        account_id=acc_id,
        tenant_id=ten_id,
        message_id="msg_001",
        internet_message_id="<msg_999@company.com>",
    )

    assert parsed.sender.address == "security@company.com"
    assert parsed.sender.name == "Security Team"
    assert parsed.recipients_to[0].address == "analyst@company.com"
    assert parsed.subject == "Urgent Action Required"
    assert parsed.has_zero_width_chars is True
    assert len(parsed.received_hops) == 1
    assert parsed.received_hops[0].client_ip == "192.168.1.50"

    assert len(parsed.urls) == 1
    assert parsed.urls[0].url == "https://login.secure.com"

    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "logo.png"
    assert att.detected_mime_type == "image/png"
    assert len(att.sha256) == 64


def test_mime_parser_engine_events() -> None:
    """Verify MimeParserEngine event emission to EventBus."""

    async def _run() -> None:
        published: list[BaseEvent] = []

        class MockPublisher:
            async def publish(self, event: BaseEvent) -> None:
                published.append(event)

        engine = MimeParserEngine(event_publisher=MockPublisher())

        raw_eml = (
            b"From: sender@test.com\r\n"
            b"To: recipient@test.com\r\n"
            b"Subject: Test Event Engine\r\n"
            b"Message-ID: <test_evt@test.com>\r\n"
            b"\r\n"
            b"Hello world"
        )

        parsed = await engine.parse_email(
            raw_eml_bytes=raw_eml,
            raw_email_id=uuid4(),
            account_id=uuid4(),
            tenant_id=uuid4(),
            message_id="msg_evt_001",
            internet_message_id="<test_evt@test.com>",
        )

        assert parsed.subject == "Test Event Engine"
        parsed_events = [e for e in published if isinstance(e, EmailParsedEvent)]
        assert len(parsed_events) == 1
        assert parsed_events[0].sender_address == "sender@test.com"

    asyncio.run(_run())


def test_parsing_module_lifecycle() -> None:
    """Verify ParsingModule DI container registration and health check lifecycle."""

    async def _run() -> None:
        di = Container()
        registry = ModuleRegistry()
        bus = InMemoryEventBus()

        mod = register_parsing_module(di, registry, event_publisher=bus)
        assert registry.get_module("parsing") == mod

        await registry.initialize_all()

        health = await registry.health_check_all()
        assert health.status == "UP"

        await registry.shutdown_all()

    asyncio.run(_run())
