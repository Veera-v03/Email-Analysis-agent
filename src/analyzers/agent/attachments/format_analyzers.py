"""Format-specific security analyzers for archives, Office docs, PDFs, and executables."""

from __future__ import annotations

import io
import zipfile

from src.analyzers.agent.attachments.base import IAttachmentAnalyzer
from src.analyzers.agent.attachments.models import AttachmentPayload
from src.models.agent import ToolEvidence

DANGEROUS_ARCHIVE_ENTRIES: set[str] = {
    "exe", "bat", "cmd", "ps1", "vbs", "js", "scr", "hta", "cpl", "jar", "iso", "dll",
}

PDF_SUSPICIOUS_KEYWORDS: tuple[tuple[bytes, str, str], ...] = (
    (b"/JavaScript", "javascript_code", "Contains active JavaScript code"),
    (b"/JS", "javascript_code", "Contains embedded JavaScript object"),
    (b"/OpenAction", "auto_action", "Executes action automatically upon opening"),
    (b"/AA", "auto_action", "Contains Additional Action trigger"),
    (b"/Launch", "file_launch", "Launches external application or process"),
    (b"/EmbeddedFile", "embedded_file", "Contains embedded file attachment"),
)

OFFICE_MACRO_KEYWORDS: tuple[bytes, ...] = (
    b"vbaProject.bin",
    b"VBA",
    b"AutoOpen",
    b"Document_Open",
    b"Workbook_Open",
    b"Auto_Open",
)


class ArchiveFormatAnalyzer(IAttachmentAnalyzer):
    """Analyze archive format attachments (ZIP, RAR, 7Z, TAR, GZ)."""

    def analyze(self, attachment: AttachmentPayload) -> list[ToolEvidence]:
        """Inspect archive content and metadata."""
        evidence: list[ToolEvidence] = []
        content = attachment.content
        filename = attachment.filename or "unnamed"

        if not content:
            return evidence

        # ZIP archive detection
        if content.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as zf:
                    info_list = zf.infolist()
                    evidence.append(
                        ToolEvidence(
                            category="attachment_archive",
                            detail=f"Attachment '{filename}' is a ZIP archive containing {len(info_list)} entries.",
                            metadata={
                                "severity": "info",
                                "confidence": 1.0,
                                "file_count": len(info_list),
                            },
                        )
                    )

                    is_encrypted = any(info.flag_bits & 0x1 for info in info_list)
                    if is_encrypted:
                        evidence.append(
                            ToolEvidence(
                                category="attachment_archive",
                                detail=f"ZIP archive '{filename}' contains password-encrypted files.",
                                metadata={
                                    "severity": "high",
                                    "confidence": 0.95,
                                    "encrypted": True,
                                },
                            )
                        )

                    # Inspect entry extensions
                    for info in info_list:
                        entry_ext = info.filename.split(".")[-1].lower() if "." in info.filename else ""
                        if entry_ext in DANGEROUS_ARCHIVE_ENTRIES:
                            evidence.append(
                                ToolEvidence(
                                    category="attachment_archive",
                                    detail=(
                                        f"ZIP archive '{filename}' contains dangerous executable file "
                                        f"'{info.filename}'."
                                    ),
                                    metadata={
                                        "severity": "critical",
                                        "confidence": 0.99,
                                        "entry_filename": info.filename,
                                        "entry_extension": entry_ext,
                                    },
                                )
                            )

                    # Zip bomb indicator (compression ratio > 100x)
                    uncompressed_total = sum(info.file_size for info in info_list)
                    compressed_total = len(content)
                    if compressed_total > 0 and uncompressed_total / compressed_total > 100:
                        evidence.append(
                            ToolEvidence(
                                category="attachment_archive",
                                detail=(
                                    f"ZIP archive '{filename}' exhibits suspicious compression ratio "
                                    f"({uncompressed_total / compressed_total:.1f}x), potential Zip Bomb."
                                ),
                                metadata={
                                    "severity": "critical",
                                    "confidence": 0.9,
                                    "compression_ratio": round(uncompressed_total / compressed_total, 2),
                                },
                            )
                        )
            except zipfile.BadZipFile:
                evidence.append(
                    ToolEvidence(
                        category="attachment_archive",
                        detail=f"Attachment '{filename}' has ZIP header but is corrupted or malformed.",
                        metadata={"severity": "medium", "confidence": 0.8},
                    )
                )

        elif content.startswith(b"Rar!\x1a\x07") or content.startswith(b"7z\xbc\xaf\x27\x1c"):
            archive_type = "RAR" if content.startswith(b"Rar!") else "7-Zip"
            evidence.append(
                ToolEvidence(
                    category="attachment_archive",
                    detail=f"Attachment '{filename}' is a compressed {archive_type} archive.",
                    metadata={
                        "severity": "info",
                        "confidence": 1.0,
                        "archive_type": archive_type,
                    },
                )
            )

        return evidence


class OfficeDocumentAnalyzer(IAttachmentAnalyzer):
    """Analyze Microsoft Office document formats for macro code or dangerous elements."""

    def analyze(self, attachment: AttachmentPayload) -> list[ToolEvidence]:
        """Analyze Office document structure and macro indicators."""
        evidence: list[ToolEvidence] = []
        content = attachment.content
        filename = attachment.filename or "unnamed"
        ext = filename.split(".")[-1].lower() if "." in filename else ""

        if not content:
            return evidence

        is_ole = content.startswith(b"\xd0\xcf\11\xe0\xa1\xb1\1a\xe1") or content.startswith(b"\xd0\xcf\x11\xe0")
        is_ooxml = content.startswith(b"PK\x03\x04") and ext in ("docx", "docm", "xlsx", "xlsm", "pptx", "pptm")

        if not (is_ole or is_ooxml or ext in ("doc", "xls", "ppt", "docm", "xlsm", "pptm")):
            return evidence

        has_macros = any(kw in content for kw in OFFICE_MACRO_KEYWORDS)
        is_macro_ext = ext in ("docm", "xlsm", "pptm", "dotm", "xltm")

        if is_ole or is_ooxml or ext:
            evidence.append(
                ToolEvidence(
                    category="attachment_office",
                    detail=f"Attachment '{filename}' is an Office Document format.",
                    metadata={
                        "severity": "info",
                        "confidence": 0.95,
                        "extension": ext,
                        "is_ole": is_ole,
                        "is_ooxml": is_ooxml,
                    },
                )
            )

        if has_macros or is_macro_ext:
            evidence.append(
                ToolEvidence(
                    category="attachment_office",
                    detail=f"Office Document '{filename}' contains active VBA macros or macro-enabled format.",
                    metadata={
                        "severity": "high",
                        "confidence": 0.95,
                        "has_macros": True,
                        "extension": ext,
                    },
                )
            )

        return evidence


class PdfFormatAnalyzer(IAttachmentAnalyzer):
    """Analyze PDF documents for embedded JavaScript, auto-actions, or launch triggers."""

    def analyze(self, attachment: AttachmentPayload) -> list[ToolEvidence]:
        """Analyze PDF header and suspicious keywords."""
        evidence: list[ToolEvidence] = []
        content = attachment.content
        filename = attachment.filename or "unnamed"

        if not content:
            return evidence

        if not (content.startswith(b"%PDF-") or b"%PDF-" in content[:1024]):
            return evidence

        evidence.append(
            ToolEvidence(
                category="attachment_pdf",
                detail=f"Attachment '{filename}' is a PDF document.",
                metadata={"severity": "info", "confidence": 1.0},
            )
        )

        for kw_bytes, category_tag, desc in PDF_SUSPICIOUS_KEYWORDS:
            if kw_bytes in content:
                severity = "high" if category_tag in ("javascript_code", "file_launch", "auto_action") else "medium"
                evidence.append(
                    ToolEvidence(
                        category="attachment_pdf",
                        detail=f"PDF document '{filename}' contains suspicious element: {desc} ({kw_bytes.decode()}).",
                        metadata={
                            "severity": severity,
                            "confidence": 0.9,
                            "keyword": kw_bytes.decode(),
                            "feature": category_tag,
                        },
                    )
                )

        return evidence


class ExecutableFormatAnalyzer(IAttachmentAnalyzer):
    """Analyze executable binaries (PE Windows, ELF Linux, Mach-O macOS, Scripts)."""

    def analyze(self, attachment: AttachmentPayload) -> list[ToolEvidence]:
        """Analyze executable headers and script hashbangs."""
        evidence: list[ToolEvidence] = []
        content = attachment.content
        filename = attachment.filename or "unnamed"

        if not content:
            return evidence

        is_pe = content.startswith(b"MZ")
        is_elf = content.startswith(b"\x7fELF")
        is_macho = content.startswith(b"\xfe\xed\xfa") or content.startswith(b"\xce\xfa\xed\xfe") or content.startswith(b"\xcf\xfa\xed\xfe")
        is_shebang = content.startswith(b"#!")

        if is_pe or is_elf or is_macho or is_shebang:
            binary_type = (
                "Windows PE Executable" if is_pe else
                "Linux ELF Executable" if is_elf else
                "macOS Mach-O Binary" if is_macho else
                "Executable Script (#!)"
            )
            evidence.append(
                ToolEvidence(
                    category="attachment_executable",
                    detail=f"Attachment '{filename}' is a raw binary executable ({binary_type}).",
                    metadata={
                        "severity": "critical",
                        "confidence": 1.0,
                        "binary_type": binary_type,
                    },
                )
            )

        return evidence
