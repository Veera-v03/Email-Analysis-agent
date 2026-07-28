"""Attachment analyzer subpackage exports."""

from src.analyzers.agent.attachments.anomaly_analyzer import AttachmentAnomalyAnalyzer
from src.analyzers.agent.attachments.base import IAttachmentAnalyzer
from src.analyzers.agent.attachments.entropy_analyzer import (
    AttachmentEntropyAnalyzer,
    calculate_shannon_entropy,
)
from src.analyzers.agent.attachments.format_analyzers import (
    ArchiveFormatAnalyzer,
    ExecutableFormatAnalyzer,
    OfficeDocumentAnalyzer,
    PdfFormatAnalyzer,
)
from src.analyzers.agent.attachments.hash_analyzer import (
    AttachmentHashAnalyzer,
    compute_attachment_hashes,
)
from src.analyzers.agent.attachments.metadata_analyzer import AttachmentMetadataAnalyzer
from src.analyzers.agent.attachments.models import (
    AttachmentAnalysisResult,
    AttachmentPayload,
    AttachmentReputationResult,
    ReputationStatus,
)
from src.analyzers.agent.attachments.reputation import (
    IAttachmentReputationProvider,
    NullAttachmentReputationProvider,
)
from src.analyzers.agent.attachments.signature_analyzer import (
    AttachmentSignatureAnalyzer,
)
from src.analyzers.agent.attachments.tool import AttachmentTool

__all__ = [
    "ArchiveFormatAnalyzer",
    "AttachmentAnalysisResult",
    "AttachmentAnomalyAnalyzer",
    "AttachmentEntropyAnalyzer",
    "AttachmentHashAnalyzer",
    "AttachmentMetadataAnalyzer",
    "AttachmentPayload",
    "AttachmentReputationResult",
    "AttachmentSignatureAnalyzer",
    "AttachmentTool",
    "ExecutableFormatAnalyzer",
    "IAttachmentAnalyzer",
    "IAttachmentReputationProvider",
    "NullAttachmentReputationProvider",
    "OfficeDocumentAnalyzer",
    "PdfFormatAnalyzer",
    "ReputationStatus",
    "calculate_shannon_entropy",
    "compute_attachment_hashes",
]
