"""Multi-stage email MIME Parsing Pipeline implementing Module 6 Specification."""

from __future__ import annotations

import email
import time
from email.message import Message
from uuid import UUID

from src.config.logging import get_logger
from src.parsing.attachments.cid_mapper import separate_attachments_and_inline_images
from src.parsing.attachments.extractor import (
    DANGEROUS_EXTENSIONS,
    extract_attachment_dto,
)
from src.parsing.body.html_normalizer import extract_text_from_html, sanitize_html_body
from src.parsing.body.mime_tree_walker import walk_mime_tree
from src.parsing.body.unicode_cleaner import (
    detect_homoglyphs,
    detect_zero_width_chars,
    normalize_unicode_nfkc,
)
from src.parsing.headers.header_parser import (
    decode_rfc2047_header,
    extract_raw_headers_map,
    parse_address_header,
    parse_addresses_list,
)
from src.parsing.headers.hop_analyzer import parse_received_hops
from src.parsing.models import (
    ExtractedAttachmentDTO,
    ExtractedURLDTO,
    ParsedEmail,
    ParsingDiagnosticDTO,
)
from src.parsing.url.url_extractor import extract_urls_from_html, extract_urls_from_text

logger = get_logger("scamon.parsing.pipeline")


class ParsingPipeline:
    """Orchestrates multi-stage RFC 5322 MIME parsing, content normalization, and entity extraction."""

    def parse(
        self,
        raw_eml_bytes: bytes,
        raw_email_id: UUID,
        account_id: UUID,
        tenant_id: UUID,
        message_id: str,
        internet_message_id: str,
    ) -> ParsedEmail:
        """Execute 8-stage parsing pipeline on raw RFC 5322 EML bytes payload."""
        start_time = time.perf_counter()
        diagnostics: list[ParsingDiagnosticDTO] = []

        # Stage 1: Parse MIME message structure
        try:
            msg: Message = email.message_from_bytes(raw_eml_bytes)
        except Exception as exc:
            logger.warning(
                "Email MIME parsing error, using empty fallback message: %s", exc
            )
            msg = Message()
            diagnostics.append(
                ParsingDiagnosticDTO(
                    code="WARN_MIME_PARSE_FALLBACK",
                    message=f"Corrupt MIME structure: {exc}",
                    severity="WARNING",
                )
            )

        # Stage 2: Header Extraction
        raw_headers = extract_raw_headers_map(msg)
        sender = parse_address_header(msg.get("From"))
        reply_to = (
            parse_address_header(msg.get("Reply-To")) if msg.get("Reply-To") else None
        )
        recipients_to = parse_addresses_list(msg.get("To"))
        recipients_cc = parse_addresses_list(msg.get("Cc"))
        recipients_bcc = parse_addresses_list(msg.get("Bcc"))
        subject = decode_rfc2047_header(msg.get("Subject", ""))

        # Stage 3: Received Hop Chain Analysis
        received_raw_list = raw_headers.get("received", [])
        received_hops = parse_received_hops(received_raw_list)

        # Stage 4: MIME Tree Traversal & Content Collector
        collected = walk_mime_tree(msg)
        raw_body_plain = "\n".join(collected.plain_parts)
        raw_body_html = "\n".join(collected.html_parts)

        # Stage 5: Pre-check Security Flags & Unicode Normalization
        has_zero_width_chars = detect_zero_width_chars(
            raw_body_plain
        ) or detect_zero_width_chars(raw_body_html)

        body_plain = normalize_unicode_nfkc(raw_body_plain)
        body_html_plain = extract_text_from_html(raw_body_html) if raw_body_html else ""
        body_html = sanitize_html_body(raw_body_html)

        # Consolidated normalized text payload for AI/LLM models
        consolidated_parts = [p for p in (body_plain, body_html_plain) if p]
        normalized_text = "\n\n".join(consolidated_parts)

        has_homoglyphs = detect_homoglyphs(normalized_text)

        # Stage 6: URL & Entity Extraction
        urls: list[ExtractedURLDTO] = []
        if raw_body_html:
            urls.extend(extract_urls_from_html(raw_body_html))
        if body_plain:
            urls.extend(extract_urls_from_text(body_plain))

        # Deduplicate URLs by target URL string
        unique_urls_map: dict[str, ExtractedURLDTO] = {}
        for u in urls:
            if u.url not in unique_urls_map:
                unique_urls_map[u.url] = u
        dedup_urls = list(unique_urls_map.values())
        has_mismatched_urls = any(u.is_mismatched for u in dedup_urls)

        # Stage 7: Attachment & Media Extraction
        all_extracted_atts: list[ExtractedAttachmentDTO] = []
        has_executable = False

        for att_part in collected.attachments_raw:
            dto = extract_attachment_dto(att_part)
            if dto:
                all_extracted_atts.append(dto)
                ext = (
                    ("." + dto.filename.split(".")[-1]).lower()
                    if "." in dto.filename
                    else ""
                )
                if (
                    ext in DANGEROUS_EXTENSIONS
                    or dto.detected_mime_type == "application/x-dsexec"
                ):
                    has_executable = True

        regular_attachments, inline_images = separate_attachments_and_inline_images(
            all_extracted_atts
        )

        # Stage 8: Assemble ParsedEmail Output Object
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return ParsedEmail(
            raw_email_id=raw_email_id,
            account_id=account_id,
            tenant_id=tenant_id,
            message_id=message_id,
            internet_message_id=internet_message_id,
            sender=sender,
            reply_to=reply_to,
            recipients_to=recipients_to,
            recipients_cc=recipients_cc,
            recipients_bcc=recipients_bcc,
            subject=subject,
            received_hops=received_hops,
            raw_headers=raw_headers,
            body_plain=body_plain,
            body_html=body_html,
            body_html_plain=body_html_plain,
            normalized_text=normalized_text,
            urls=dedup_urls,
            attachments=regular_attachments,
            inline_images=inline_images,
            has_zero_width_chars=has_zero_width_chars,
            has_homoglyphs=has_homoglyphs,
            has_mismatched_urls=has_mismatched_urls,
            has_executable_attachments=has_executable,
            parsing_time_ms=elapsed_ms,
            diagnostics=diagnostics,
        )
