"""Strict data contracts used by the application."""

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
from src.models.config import ApplicationConfig
from src.models.email import EmailAttachment, EmailHeader, EmailInput
from src.models.evidence import Evidence, EvidenceCollection, EvidenceSeverity
from src.models.sender import ParsedEmailAddress, SenderAnalysisResult

__all__ = [
    "AgentState",
    "ApplicationConfig",
    "EmailAttachment",
    "EmailHeader",
    "EmailInput",
    "Evidence",
    "EvidenceCollection",
    "EvidenceSeverity",
    "ExecutionRecord",
    "ParsedEmailAddress",
    "PlanningDecision",
    "SenderAnalysisResult",
    "ToolCapability",
    "ToolErrorInfo",
    "ToolEvidence",
    "ToolExecutionStatus",
    "ToolMetadata",
    "ToolResult",
]
