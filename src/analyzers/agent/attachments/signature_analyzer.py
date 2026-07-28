"""File signature (magic bytes) analyzer and MIME validator."""

from __future__ import annotations

from src.analyzers.agent.attachments.base import IAttachmentAnalyzer
from src.analyzers.agent.attachments.models import AttachmentPayload
from src.models.agent import ToolEvidence

MAGIC_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"%PDF-", "application/pdf", "PDF Document"),
    (b"PK\x03\x04", "application/zip", "ZIP Archive / OpenXML"),
    (b"MZ", "application/x-dosexec", "PE Windows Executable"),
    (b"\x7fELF", "application/x-executable", "Linux ELF Executable"),
    (b"\xfe\xed\xfa", "application/x-mach-binary", "macOS Mach-O Executable"),
    (b"\xce\xfa\xed\xfe", "application/x-mach-binary", "macOS Mach-O Executable"),
    (b"\xcf\xfa\xed\xfe", "application/x-mach-binary", "macOS Mach-O Executable"),
    (b"Rar!\x1a\x07", "application/x-rar-compressed", "RAR Archive"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7-Zip Archive"),
    (b"\x1f\x8b", "application/gzip", "GZIP Archive"),
    (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        "application/msword",
        "OLE2 Compound Document",
    ),
    (b"\xff\xd8\xff", "image/jpeg", "JPEG Image"),
    (b"\x89PNG\r\n\x1a\n", "image/png", "PNG Image"),
    (b"GIF87a", "image/gif", "GIF Image"),
    (b"GIF89a", "image/gif", "GIF Image"),
    (b"BM", "image/bmp", "BMP Image"),
)

EXEC_MIMES = (
    "application/x-dosexec",
    "application/x-executable",
    "application/x-mach-binary",
)
SAFE_DECLARED_MIMES = (
    "image/jpeg",
    "image/png",
    "application/pdf",
    "text/plain",
    "application/msword",
)


def detect_magic_mime(content: bytes) -> tuple[str, str] | None:
    """Identify MIME type and description from content magic bytes."""
    if not content:
        return None
    for signature, mime_type, description in MAGIC_SIGNATURES:
        if content.startswith(signature):
            return mime_type, description
    return None


class AttachmentSignatureAnalyzer(IAttachmentAnalyzer):
    """Analyze magic number signatures and validate against declared MIME types."""

    def analyze(self, attachment: AttachmentPayload) -> list[ToolEvidence]:
        """Analyze file signature and detect MIME mismatches."""
        evidence: list[ToolEvidence] = []
        filename = attachment.filename or "unnamed"
        content = attachment.content

        if not content:
            return evidence

        magic_info = detect_magic_mime(content)
        if not magic_info:
            return evidence

        detected_mime, format_desc = magic_info
        declared_mime = attachment.content_type.strip().lower()

        # Emit signature match evidence
        evidence.append(
            ToolEvidence(
                category="attachment_signature",
                detail=(
                    f"Attachment '{filename}' matches magic signature for {format_desc} "
                    f"({detected_mime})."
                ),
                metadata={
                    "severity": "info",
                    "confidence": 1.0,
                    "detected_mime": detected_mime,
                    "format_description": format_desc,
                },
            )
        )

        # Check for MIME mismatch
        if (
            declared_mime
            and declared_mime != "application/octet-stream"
            and declared_mime != detected_mime
        ):
            is_executable_disguised = (
                detected_mime in EXEC_MIMES and declared_mime in SAFE_DECLARED_MIMES
            )
            severity = "critical" if is_executable_disguised else "high"
            evidence.append(
                ToolEvidence(
                    category="attachment_signature",
                    detail=(
                        f"MIME Mismatch in attachment '{filename}': declared '{declared_mime}' "
                        f"but detected '{detected_mime}' ({format_desc})."
                    ),
                    metadata={
                        "severity": severity,
                        "confidence": 0.98,
                        "declared_mime": declared_mime,
                        "detected_mime": detected_mime,
                        "is_executable_disguised": is_executable_disguised,
                    },
                )
            )

        return evidence
