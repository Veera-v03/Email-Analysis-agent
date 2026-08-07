"""Content-ID (CID) inline image mapping utilities."""

from __future__ import annotations

from src.parsing.models import ExtractedAttachmentDTO


def separate_attachments_and_inline_images(
    attachments: list[ExtractedAttachmentDTO],
) -> tuple[list[ExtractedAttachmentDTO], list[ExtractedAttachmentDTO]]:
    """Separate list of attachments into standard attachments and inline CID images."""
    regular_attachments: list[ExtractedAttachmentDTO] = []
    inline_images: list[ExtractedAttachmentDTO] = []

    for att in attachments:
        if att.is_inline or (att.content_id and "image/" in att.detected_mime_type):
            inline_images.append(att)
        else:
            regular_attachments.append(att)

    return regular_attachments, inline_images
