"""Media Processor coordinating OCR text extraction and QR code decoding across attachments."""

from __future__ import annotations

from src.content_intelligence.models import ContentMediaEvidenceDTO, MediaStatus
from src.parsing.models import ParsedEmail
from src.security_intelligence.ocr.ocr_service import OCRService
from src.security_intelligence.qr.qr_service import QRService


class MediaProcessor:
    """Processes image and PDF attachments using extended OCRService and QRService."""

    def __init__(
        self,
        ocr_service: OCRService | None = None,
        qr_service: QRService | None = None,
    ) -> None:
        self.ocr_service = ocr_service or OCRService()
        self.qr_service = qr_service or QRService()

    def process_media(self, parsed: ParsedEmail) -> ContentMediaEvidenceDTO:
        """Scan email attachments for OCR text and QR codes with honest status tracking."""
        attachments = parsed.attachments + parsed.inline_images
        if not attachments:
            return ContentMediaEvidenceDTO(
                ocr_status=MediaStatus.SKIPPED,
                qr_status=MediaStatus.SKIPPED,
            )

        extracted_texts: list[str] = []
        overall_ocr_conf = 0.0
        ocr_status = MediaStatus.SKIPPED

        qr_detected = False
        qr_urls: list[str] = []
        qr_status = MediaStatus.SKIPPED

        for att in attachments:
            content: bytes = (
                getattr(att, "raw_data", None)
                or getattr(att, "content_bytes", None)
                or b""
            )

            # 1. OCR Extraction
            ocr_res = self.ocr_service.extract_text(att.filename, content)
            raw_ocr_status = str(ocr_res.get("status", "SKIPPED"))
            if raw_ocr_status == "SUCCESS":
                ocr_status = MediaStatus.SUCCESS
                txt = str(ocr_res.get("extracted_text", ""))
                if txt:
                    extracted_texts.append(txt)
                overall_ocr_conf = max(
                    overall_ocr_conf, float(ocr_res.get("confidence", 0.0))
                )
            elif raw_ocr_status == "UNAVAILABLE" and ocr_status != MediaStatus.SUCCESS:
                ocr_status = MediaStatus.UNAVAILABLE

            # 2. QR Code Decoding
            qr_res = self.qr_service.extract_and_decode(att.filename, content)
            raw_qr_status = str(qr_res.get("status", "SKIPPED"))
            if raw_qr_status == "SUCCESS":
                qr_status = MediaStatus.SUCCESS
                if qr_res.get("qr_detected"):
                    qr_detected = True
                    raw_url = qr_res.get("raw_url")
                    res_url = qr_res.get("resolved_url")
                    if raw_url:
                        qr_urls.append(str(raw_url))
                    if res_url and res_url != raw_url:
                        qr_urls.append(str(res_url))
            elif raw_qr_status == "UNAVAILABLE" and qr_status != MediaStatus.SUCCESS:
                qr_status = MediaStatus.UNAVAILABLE

        return ContentMediaEvidenceDTO(
            ocr_status=ocr_status,
            ocr_extracted_text="\n".join(extracted_texts),
            ocr_confidence=overall_ocr_conf,
            qr_status=qr_status,
            qr_detected=qr_detected,
            qr_extracted_urls=sorted(list(set(qr_urls))),
        )
