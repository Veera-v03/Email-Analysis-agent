"""Filename anomaly, double extension, and dangerous extension analyzer."""

from __future__ import annotations

import re

from src.analyzers.agent.attachments.base import IAttachmentAnalyzer
from src.analyzers.agent.attachments.models import AttachmentPayload
from src.models.agent import ToolEvidence

DANGEROUS_EXTENSIONS: set[str] = {
    "exe",
    "bat",
    "cmd",
    "ps1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
    "scr",
    "hta",
    "cpl",
    "jar",
    "iso",
    "img",
    "chm",
    "dll",
    "lnk",
    "inf",
    "reg",
    "msi",
    "msp",
    "gadget",
    "bas",
    "pif",
    "com",
    "vxd",
    "sys",
}

SAFE_NON_EXEC_EXTENSIONS: set[str] = {
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "txt",
    "rtf",
    "jpg",
    "jpeg",
    "png",
    "gif",
    "bmp",
    "csv",
    "mp3",
    "mp4",
    "zip",
}

# Right-to-Left Override character (U+202E) used in spoofing filenames
RTLO_CHAR = "\u202e"


class AttachmentAnomalyAnalyzer(IAttachmentAnalyzer):
    """Analyze filename anomalies, double extensions, and dangerous file extensions."""

    def analyze(self, attachment: AttachmentPayload) -> list[ToolEvidence]:
        """Analyze filename for security anomalies."""
        evidence: list[ToolEvidence] = []
        filename = attachment.filename.strip()

        if not filename:
            return evidence

        # 1. Right-To-Left Override (RTLO) detection
        if RTLO_CHAR in filename:
            evidence.append(
                ToolEvidence(
                    category="attachment_anomaly",
                    detail=(
                        f"Attachment filename '{filename}' contains dangerous Unicode "
                        "Right-to-Left Override character."
                    ),
                    metadata={
                        "severity": "critical",
                        "confidence": 1.0,
                        "anomaly": "rtlo_character_detected",
                    },
                )
            )

        # 2. Control characters in filename
        if any(ord(c) < 32 for c in filename):
            evidence.append(
                ToolEvidence(
                    category="attachment_anomaly",
                    detail=f"Attachment filename '{filename}' contains hidden control characters.",
                    metadata={
                        "severity": "high",
                        "confidence": 0.95,
                        "anomaly": "control_characters_detected",
                    },
                )
            )

        # 3. Trailing spaces or trailing dots (Windows file extension trick)
        if filename != filename.rstrip(" ."):
            evidence.append(
                ToolEvidence(
                    category="attachment_anomaly",
                    detail=f"Attachment filename '{filename}' contains trailing spaces or dots.",
                    metadata={
                        "severity": "high",
                        "confidence": 0.9,
                        "anomaly": "trailing_whitespace_or_dots",
                    },
                )
            )

        # 4. Excessive hidden whitespace in filename (e.g. invoice.pdf             .exe)
        if re.search(r"\.[a-zA-Z0-9]{2,4}\s{5,}\.[a-zA-Z0-9]{2,4}$", filename):
            evidence.append(
                ToolEvidence(
                    category="attachment_anomaly",
                    detail=(
                        f"Attachment filename '{filename}' contains excessive spaces "
                        "intended to hide true extension."
                    ),
                    metadata={
                        "severity": "critical",
                        "confidence": 0.98,
                        "anomaly": "hidden_extension_spaces",
                    },
                )
            )

        # Split extensions
        parts = [p.lower() for p in filename.split(".") if p]
        if len(parts) > 1:
            primary_ext = parts[-1]

            # 5. Dangerous extension detection
            if primary_ext in DANGEROUS_EXTENSIONS:
                evidence.append(
                    ToolEvidence(
                        category="attachment_anomaly",
                        detail=(
                            f"Attachment '{filename}' has dangerous executable "
                            f"extension '.{primary_ext}'."
                        ),
                        metadata={
                            "severity": "high",
                            "confidence": 0.95,
                            "extension": primary_ext,
                        },
                    )
                )

            # 6. Double extension detection (e.g. document.pdf.exe)
            if len(parts) >= 3:
                second_last_ext = parts[-2]
                if (
                    second_last_ext in SAFE_NON_EXEC_EXTENSIONS
                    and primary_ext in DANGEROUS_EXTENSIONS
                ):
                    evidence.append(
                        ToolEvidence(
                            category="attachment_anomaly",
                            detail=(
                                f"Double extension anomaly in attachment '{filename}': "
                                f"spoofed document extension '.{second_last_ext}' "
                                f"followed by dangerous extension '.{primary_ext}'."
                            ),
                            metadata={
                                "severity": "critical",
                                "confidence": 0.99,
                                "outer_extension": second_last_ext,
                                "real_extension": primary_ext,
                            },
                        )
                    )

        # 7. Extremely long filename
        if len(filename) > 150:
            evidence.append(
                ToolEvidence(
                    category="attachment_anomaly",
                    detail=(
                        f"Attachment filename '{filename[:30]}...' is suspiciously long "
                        f"({len(filename)} characters)."
                    ),
                    metadata={
                        "severity": "low",
                        "confidence": 0.7,
                        "length": len(filename),
                    },
                )
            )

        return evidence
