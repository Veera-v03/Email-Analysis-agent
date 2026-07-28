from __future__ import annotations

import io
import zipfile

from src.analyzers.agent.attachments import AttachmentTool
from src.analyzers.agent.attachments.entropy_analyzer import calculate_shannon_entropy
from src.analyzers.agent.attachments.hash_analyzer import compute_attachment_hashes
from src.analyzers.agent.attachments.models import AttachmentPayload, ReputationStatus
from src.analyzers.agent.attachments.reputation import NullAttachmentReputationProvider
from src.analyzers.agent.registry import ToolRegistry
from src.models.agent import AgentState, ToolCapability, ToolExecutionStatus
from src.models.email import EmailAttachment, EmailHeader, EmailInput


def test_attachment_tool_execution_with_no_attachments() -> None:
    tool = AttachmentTool()
    state = AgentState.create()

    result = tool.execute(state)

    assert result.status is ToolExecutionStatus.COMPLETED
    assert result.metadata["attachments_analyzed"] == 0
    assert result.metadata["has_attachments"] is False
    assert result.evidence == ()


def test_attachment_tool_metadata_validation() -> None:
    tool = AttachmentTool()
    sample_email = EmailInput(
        header=EmailHeader(
            message_id="<att1@example.com>",
            sender="sender@example.com",
            recipients=["rcpt@example.com"],
            subject="Attachment Test",
            sent_at="2026-07-28T10:00:00Z",
        ),
        body_text="See attached files",
        attachments=[
            EmailAttachment(filename="   ", content_type="  ", size_bytes=0),
            EmailAttachment(
                filename="data.bin",
                content_type="application/octet-stream",
                size_bytes=100,
            ),
        ],
    )
    state = AgentState.create(parsed_email=sample_email)

    result = tool.execute(state)

    assert result.status is ToolExecutionStatus.COMPLETED
    assert result.metadata["attachments_analyzed"] == 2
    assert len(result.evidence) >= 3

    categories = [ev.category for ev in result.evidence]
    assert "attachment_metadata" in categories


def test_attachment_tool_magic_bytes_and_mime_mismatch() -> None:
    tool = AttachmentTool()
    # Executable disguised as image/jpeg
    fake_jpeg_content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"
    payload = AttachmentPayload(
        filename="photo.jpg",
        content_type="image/jpeg",
        size_bytes=len(fake_jpeg_content),
        content=fake_jpeg_content,
    )
    state = AgentState.create(metadata={"attachment_payloads": [payload]})

    result = tool.execute(state)

    assert result.status is ToolExecutionStatus.COMPLETED
    assert result.metadata["attachments_analyzed"] == 1

    evidence_list = result.evidence
    mismatch_ev = [ev for ev in evidence_list if "MIME Mismatch" in ev.detail]
    assert len(mismatch_ev) == 1
    assert mismatch_ev[0].metadata["severity"] == "critical"
    assert mismatch_ev[0].metadata["detected_mime"] == "application/x-dosexec"


def test_attachment_tool_double_extension_rtlo_and_dangerous_extension() -> None:
    tool = AttachmentTool()
    rtlo_filename = "invoice\u202epdf.exe"
    payload_1 = AttachmentPayload(
        filename="document.pdf.exe",
        content_type="application/pdf",
        size_bytes=50,
        content=b"Dummy executable content",
    )
    payload_2 = AttachmentPayload(
        filename=rtlo_filename,
        content_type="application/x-msdownload",
        size_bytes=50,
        content=b"Dummy content",
    )
    payload_3 = AttachmentPayload(
        filename="script.vbs",
        content_type="text/plain",
        size_bytes=20,
        content=b"WScript.Echo 'Hello'",
    )
    state = AgentState.create(
        metadata={"attachment_payloads": [payload_1, payload_2, payload_3]}
    )

    result = tool.execute(state)

    assert result.status is ToolExecutionStatus.COMPLETED
    assert result.metadata["attachments_analyzed"] == 3

    categories = [ev.category for ev in result.evidence]
    assert "attachment_anomaly" in categories

    details = [ev.detail for ev in result.evidence]
    assert any("Double extension anomaly" in d for d in details)
    assert any("Right-to-Left Override" in d for d in details)
    assert any("dangerous executable extension '.vbs'" in d for d in details)


def test_attachment_entropy_and_hash_calculation() -> None:
    content = bytes([i % 256 for i in range(2000)])
    entropy = calculate_shannon_entropy(content)
    sha256, md5 = compute_attachment_hashes(content)

    assert entropy > 7.5
    assert len(sha256) == 64
    assert len(md5) == 32

    tool = AttachmentTool()
    payload = AttachmentPayload(
        filename="packed_data.bin",
        content_type="application/octet-stream",
        size_bytes=len(content),
        content=content,
    )
    state = AgentState.create(metadata={"attachment_payloads": [payload]})

    result = tool.execute(state)
    assert result.status is ToolExecutionStatus.COMPLETED

    categories = [ev.category for ev in result.evidence]
    assert "attachment_entropy" in categories
    assert "attachment_hash" in categories

    hash_ev = [ev for ev in result.evidence if ev.category == "attachment_hash"][0]
    assert hash_ev.metadata["sha256"] == sha256


def test_attachment_tool_zip_archive_analysis() -> None:
    tool = AttachmentTool()

    # Create in-memory zip containing dangerous file
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test.txt", "Hello World")
        zf.writestr("malicious.exe", b"MZ fake executable")

    zip_bytes = zip_buffer.getvalue()
    payload = AttachmentPayload(
        filename="archive.zip",
        content_type="application/zip",
        size_bytes=len(zip_bytes),
        content=zip_bytes,
    )
    state = AgentState.create(metadata={"attachment_payloads": [payload]})

    result = tool.execute(state)

    assert result.status is ToolExecutionStatus.COMPLETED
    details = [ev.detail for ev in result.evidence]
    assert any("ZIP archive containing 2 entries" in d for d in details)
    assert any("dangerous executable file 'malicious.exe'" in d for d in details)


def test_attachment_tool_office_macro_detection() -> None:
    tool = AttachmentTool()
    macro_content = b"PK\x03\x04...word/vbaProject.bin...AutoOpen...Workbook_Open..."
    payload = AttachmentPayload(
        filename="invoice.docm",
        content_type="application/vnd.ms-word.document.macroenabled.12",
        size_bytes=len(macro_content),
        content=macro_content,
    )
    state = AgentState.create(metadata={"attachment_payloads": [payload]})

    result = tool.execute(state)

    assert result.status is ToolExecutionStatus.COMPLETED
    details = [ev.detail for ev in result.evidence]
    assert any("contains active VBA macros" in d for d in details)


def test_attachment_tool_pdf_javascript_detection() -> None:
    tool = AttachmentTool()
    pdf_content = (
        b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\n"
        b"endobj\n3 0 obj\n<< /S /JavaScript /JS (app.alert('Phishing')) >>\nendobj\n"
    )
    payload = AttachmentPayload(
        filename="statement.pdf",
        content_type="application/pdf",
        size_bytes=len(pdf_content),
        content=pdf_content,
    )
    state = AgentState.create(metadata={"attachment_payloads": [payload]})

    result = tool.execute(state)

    assert result.status is ToolExecutionStatus.COMPLETED
    details = [ev.detail for ev in result.evidence]
    assert any("Contains active JavaScript code" in d for d in details)
    assert any("Executes action automatically" in d for d in details)


def test_attachment_tool_executable_detection() -> None:
    tool = AttachmentTool()
    elf_content = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    payload = AttachmentPayload(
        filename="binary.elf",
        content_type="application/x-executable",
        size_bytes=len(elf_content),
        content=elf_content,
    )
    state = AgentState.create(metadata={"attachment_payloads": [payload]})

    result = tool.execute(state)

    assert result.status is ToolExecutionStatus.COMPLETED
    details = [ev.detail for ev in result.evidence]
    assert any("Linux ELF Executable" in d for d in details)


def test_null_attachment_reputation_provider() -> None:
    provider = NullAttachmentReputationProvider()
    rep = provider.check_hash("a" * 64)

    assert rep.sha256 == "a" * 64
    assert rep.status is ReputationStatus.UNKNOWN
    assert rep.score == 0.0


def test_attachment_tool_registry_integration() -> None:
    registry = ToolRegistry()
    tool = AttachmentTool()

    registry.register(tool)
    assert registry.has_tool("attachment_tool")

    retrieved = registry.get("attachment_tool")
    assert retrieved is tool
    assert ToolCapability.ATTACHMENT in retrieved.metadata.capabilities
