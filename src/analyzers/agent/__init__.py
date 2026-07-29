"""Phase 5 agent foundation exports."""

# pyrefly: ignore [missing-import]
from src.analyzers.agent.attachments import AttachmentTool
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
from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.engine import (
    ExecutionOptions,
    ExecutionResult,
    ExecutionSummary,
    ToolExecutionEngine,
)
from src.analyzers.agent.evidence import EvidenceAggregator, EvidenceBuilder
from src.analyzers.agent.exceptions import (
    DuplicateToolError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolRegistryError,
    ToolValidationError,
)
from src.analyzers.agent.registry import IToolRegistry, ToolRegistry
from src.analyzers.agent.tools.parser_tool import ParserTool
from src.analyzers.agent.tools.report_tool import ReportTool
from src.analyzers.agent.tools.sender_tool import SenderTool
from src.analyzers.agent.tools.url_tool import URLTool
from src.models.agent import (
    AgentState,
    ExecutionRecord,
    PlanningDecision,
    ToolCapability,
    ToolErrorInfo,
    ToolEvidence,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)
from src.models.evidence import Evidence, EvidenceCollection, EvidenceSeverity

__all__ = [
    "AgentState",
    "AgentTool",
    "AttachmentAnalysisResult",
    "AttachmentPayload",
    "AttachmentReputationResult",
    "AttachmentTool",
    "DuplicateToolError",
    "EvidenceAggregator",
    "EvidenceBuilder",
    "Evidence",
    "EvidenceCollection",
    "EvidenceSeverity",
    "ExecutionOptions",
    "ExecutionResult",
    "ExecutionSummary",
    "ExecutionRecord",
    "IAttachmentReputationProvider",
    "IToolRegistry",
    "NullAttachmentReputationProvider",
    "ParserTool",
    "PlanningDecision",
    "ReportTool",
    "ReputationStatus",
    "SenderTool",
    "ToolCapability",
    "ToolErrorInfo",
    "ToolExecutionEngine",
    "ToolEvidence",
    "ToolExecutionError",
    "ToolExecutionStatus",
    "ToolMetadata",
    "ToolNotFoundError",
    "ToolRegistry",
    "ToolRegistryError",
    "ToolResult",
    "ToolValidationError",
    "URLTool",
]
