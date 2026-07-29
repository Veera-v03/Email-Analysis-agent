"""Production-ready AttachmentTool integrating with the AgentState ecosystem."""

from __future__ import annotations

import time

from src.analyzers.agent.attachments.anomaly_analyzer import AttachmentAnomalyAnalyzer
from src.analyzers.agent.attachments.base import IAttachmentAnalyzer
from src.analyzers.agent.attachments.entropy_analyzer import AttachmentEntropyAnalyzer
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
from src.analyzers.agent.attachments.models import AttachmentPayload
from src.analyzers.agent.attachments.reputation import (
    IAttachmentReputationProvider,
    NullAttachmentReputationProvider,
)
from src.analyzers.agent.attachments.signature_analyzer import (
    AttachmentSignatureAnalyzer,
)
from src.analyzers.agent.attachments.yara_analyzer import IYaraScanner, YaraRuleAnalyzer
from src.analyzers.agent.contracts import AgentTool
from src.analyzers.agent.enterprise_intelligence import EnterpriseIntelligenceService
from src.models.agent import (
    AgentState,
    ToolCapability,
    ToolEvidence,
    ToolExecutionStatus,
    ToolMetadata,
    ToolResult,
)


class AttachmentTool(AgentTool[AgentState]):
    """Analyze email attachments independently using modular security components."""

    def __init__(
        self,
        metadata: ToolMetadata | None = None,
        analyzers: tuple[IAttachmentAnalyzer, ...] | None = None,
        reputation_provider: IAttachmentReputationProvider | None = None,
        enterprise_intelligence: EnterpriseIntelligenceService | None = None,
        yara_scanner: IYaraScanner | None = None,
    ) -> None:
        default_metadata = ToolMetadata(
            name="attachment_tool",
            description=(
                "Analyzes email attachments for security anomalies and magic bytes."
            ),
            version="1.0.0",
            capabilities=(ToolCapability.ATTACHMENT,),
            tags=("attachment", "security", "malware_analysis"),
        )
        super().__init__(metadata or default_metadata)
        default_analyzers: tuple[IAttachmentAnalyzer, ...] = (
            AttachmentMetadataAnalyzer(),
            AttachmentSignatureAnalyzer(),
            AttachmentAnomalyAnalyzer(),
            AttachmentEntropyAnalyzer(),
            AttachmentHashAnalyzer(),
            ArchiveFormatAnalyzer(),
            OfficeDocumentAnalyzer(),
            PdfFormatAnalyzer(),
            ExecutableFormatAnalyzer(),
        )
        if yara_scanner is not None:
            default_analyzers += (YaraRuleAnalyzer(yara_scanner),)
        self._analyzers = analyzers or default_analyzers
        self._reputation_provider: IAttachmentReputationProvider = (
            reputation_provider or NullAttachmentReputationProvider()
        )
        self._enterprise_intelligence = enterprise_intelligence

    def execute(self, input_data: AgentState) -> ToolResult:
        """Execute modular attachment security analysis on AgentState attachments."""
        start_ns = time.perf_counter_ns()
        payloads = self._extract_payloads(input_data)

        if not payloads:
            elapsed_ms = max(0, int((time.perf_counter_ns() - start_ns) / 1_000_000))
            return ToolResult(
                tool_name=self.metadata.name,
                status=ToolExecutionStatus.COMPLETED,
                metadata={"attachments_analyzed": 0, "has_attachments": False},
                evidence=(),
                execution_time_ms=elapsed_ms,
            )

        all_evidence: list[ToolEvidence] = []
        analyzed_count = 0

        for payload in payloads:
            analyzed_count += 1
            for analyzer in self._analyzers:
                try:
                    all_evidence.extend(analyzer.analyze(payload))
                except Exception as error:
                    all_evidence.append(
                        ToolEvidence(
                            category="attachment_analyzer_diagnostic",
                            detail=(
                                f"{analyzer.__class__.__name__} could not analyze "
                                f"'{payload.filename}': {error}"
                            ),
                            metadata={
                                "severity": "info",
                                "analyzer": analyzer.__class__.__name__,
                                "filename": payload.filename,
                                "exception_type": error.__class__.__name__,
                            },
                        )
                    )

            # Reputation check if content bytes are present
            if payload.content:
                sha256, _ = compute_attachment_hashes(payload.content)
                rep_result = self._reputation_provider.check_hash(sha256)
                if rep_result.status.value in ("suspicious", "malicious"):
                    is_mal = rep_result.status.value == "malicious"
                    sev = "critical" if is_mal else "high"
                    all_evidence.append(
                        ToolEvidence(
                            category="attachment_reputation",
                            detail=(
                                f"Attachment '{payload.filename}' flagged as "
                                f"{rep_result.status.value} by reputation provider."
                            ),
                            metadata={
                                "severity": sev,
                                "confidence": 0.95,
                                "sha256": sha256,
                                "status": rep_result.status.value,
                            },
                        )
                    )

                if self._enterprise_intelligence is not None:
                    all_evidence.extend(
                        self._enterprise_reputation_evidence(payload.filename, sha256)
                    )

        elapsed_ms = max(0, int((time.perf_counter_ns() - start_ns) / 1_000_000))
        return ToolResult(
            tool_name=self.metadata.name,
            status=ToolExecutionStatus.COMPLETED,
            metadata={
                "attachments_analyzed": analyzed_count,
                "has_attachments": True,
                "total_evidence_generated": len(all_evidence),
            },
            evidence=tuple(all_evidence),
            execution_time_ms=elapsed_ms,
        )

    def _enterprise_reputation_evidence(
        self, filename: str, sha256: str
    ) -> tuple[ToolEvidence, ...]:
        """Add optional cached external hash intelligence without affecting analysis."""
        if self._enterprise_intelligence is None:
            return ()
        enrichment = self._enterprise_intelligence.enrich(sha256)
        evidence: list[ToolEvidence] = []
        for observation in enrichment.observations:
            evidence.append(
                ToolEvidence(
                    category=f"attachment_enterprise_{observation.provider_name}",
                    detail=observation.summary,
                    metadata={
                        "severity": "high" if observation.malicious else "info",
                        "confidence": observation.confidence,
                        "provider": observation.provider_name,
                        "filename": filename,
                        "sha256": sha256,
                        "from_cache": enrichment.from_cache,
                        **observation.metadata,
                    },
                )
            )
        for diagnostic in enrichment.diagnostics:
            evidence.append(
                ToolEvidence(
                    category="attachment_enterprise_diagnostic",
                    detail=f"{diagnostic.provider_name}: {diagnostic.reason}",
                    metadata={
                        "severity": "info",
                        "provider": diagnostic.provider_name,
                        "filename": filename,
                        "sha256": sha256,
                    },
                )
            )
        return tuple(evidence)

    def _extract_payloads(self, state: AgentState) -> list[AttachmentPayload]:
        """Extract attachment payloads from AgentState without modifying state."""
        payloads: list[AttachmentPayload] = []

        # 1. Check for raw payloads attached in state metadata
        raw_payloads = state.metadata.get("attachment_payloads")
        if isinstance(raw_payloads, list):
            for item in raw_payloads:
                if isinstance(item, AttachmentPayload):
                    payloads.append(item)
                elif isinstance(item, dict):
                    payloads.append(AttachmentPayload.model_validate(item))

        if payloads:
            return payloads

        # 2. Check parsed_email attachments metadata
        if state.parsed_email and state.parsed_email.attachments:
            for att in state.parsed_email.attachments:
                payloads.append(
                    AttachmentPayload(
                        filename=att.filename,
                        content_type=att.content_type,
                        size_bytes=att.size_bytes,
                        content=b"",
                    )
                )

        return payloads
