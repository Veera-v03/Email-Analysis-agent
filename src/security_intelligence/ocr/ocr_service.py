"""OCR Intelligence Service for extracting structured text from images and scanned PDF attachments."""

from __future__ import annotations

import re
from typing import Any


class OCRService:
    """Simulates OCR text extraction and text normalization for security scanning."""

    def extract_text(self, filename: str, content: bytes) -> dict[str, Any]:
        """Extract text from simulated image or scanned document bytes.

        Returns:
            {
                "extracted_text": str,
                "confidence": float,
                "metadata": dict
            }
        """
        fn_lower = filename.lower()
        if not (
            fn_lower.endswith((".png", ".jpg", ".jpeg", ".gif", ".pdf"))
            or b"png" in content[:10]
            or b"JFIF" in content[:10]
            or b"%PDF" in content[:10]
        ):
            return {"extracted_text": "", "confidence": 0.0, "metadata": {}}

        # Default fallback text simulations based on patterns in the filename or byte signature
        confidence = 0.92
        extracted = ""

        # Check if the mock content contains specific patterns for testing
        content_str = ""
        try:
            content_str = content.decode("utf-8", errors="ignore")
        except Exception:
            pass

        # Simulate detecting phishing keywords in OCR text
        if "invoice" in fn_lower or "invoice" in content_str.lower():
            extracted = "URGENT PAYMENT DUE. Invoice #2026-9871. Please wire $5,000 immediately to Routing 12345."
            confidence = 0.95
        elif "bank" in fn_lower or "bank" in content_str.lower():
            extracted = "Security alert from Bank. Your account has been temporarily disabled. Reset your password immediately."
            confidence = 0.89
        elif "qr" in fn_lower or "qr" in content_str.lower():
            extracted = "Scan this QR code to confirm your Google sign-in request."
            confidence = 0.94
        else:
            # Default mock text extraction
            extracted = f"Simulated OCR text content from {filename}."
            confidence = 0.90

        # Normalization: strip whitespaces, resolve double spaces, convert typical visual typos
        normalized = re.sub(r"\s+", " ", extracted).strip()

        return {
            "extracted_text": normalized,
            "confidence": confidence,
            "metadata": {
                "filename": filename,
                "file_size_bytes": len(content),
                "resolution_dpi": 300,
                "language": "en",
            },
        }
