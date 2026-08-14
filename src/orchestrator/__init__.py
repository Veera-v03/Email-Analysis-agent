"""Pipeline Orchestrator Package for ScamON Enterprise."""

from __future__ import annotations

from src.orchestrator.engine import OrchestratorEngine
from src.orchestrator.exceptions import (
    OrchestratorError,
    PipelineCancelledError,
    SLABreachError,
    StageFailureError,
)
from src.orchestrator.hooks import PipelineLifecycleHooks
from src.orchestrator.models import (
    EmailAnalysisResult,
    PipelineContext,
    StageClassification,
    StageResult,
    StageStatus,
)
from src.orchestrator.module import OrchestratorModule, register_orchestrator_module
from src.orchestrator.orchestrator import EmailSecurityPipelineOrchestrator
from src.orchestrator.sla_monitor import SLAMonitoringEngine

__all__ = [
    "EmailAnalysisResult",
    "EmailSecurityPipelineOrchestrator",
    "OrchestratorEngine",
    "OrchestratorError",
    "OrchestratorModule",
    "PipelineCancelledError",
    "PipelineContext",
    "PipelineLifecycleHooks",
    "SLABreachError",
    "SLAMonitoringEngine",
    "StageClassification",
    "StageFailureError",
    "StageResult",
    "StageStatus",
    "register_orchestrator_module",
]
