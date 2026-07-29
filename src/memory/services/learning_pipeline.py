"""Learning pipeline ingesting completed investigations into the memory subsystem."""

from __future__ import annotations

from datetime import UTC, datetime

from src.memory.embeddings.embedding_provider import IEmbeddingProvider
from src.memory.models.memory_models import (
    AttachmentMemory,
    EvidenceMemory,
    InvestigationMemory,
    PatternMemory,
    SenderMemory,
    ThreatMemory,
    URLMemory,
)
from src.memory.repositories.memory_repository import (
    AttachmentRepository,
    EvidenceRepository,
    InvestigationRepository,
    PatternRepository,
    SenderRepository,
    ThreatRepository,
    URLRepository,
)
from src.memory.storage.vector_store import IVectorStore
from src.models.agent import AgentState
from src.planner.explainability import FinalReport
from src.planner.reasoning import ReasoningOutput


class LearningPipeline:
    """Automates post-investigation learning by ingesting AgentState and reasoning results."""

    def __init__(
        self,
        vector_store: IVectorStore,
        embedding_provider: IEmbeddingProvider,
    ) -> None:
        self.vector_store = vector_store
        self.embedding_provider = embedding_provider

        self.investigation_repo = InvestigationRepository(
            vector_store, embedding_provider
        )
        self.evidence_repo = EvidenceRepository(vector_store, embedding_provider)
        self.threat_repo = ThreatRepository(vector_store, embedding_provider)
        self.sender_repo = SenderRepository(vector_store, embedding_provider)
        self.url_repo = URLRepository(vector_store, embedding_provider)
        self.attachment_repo = AttachmentRepository(vector_store, embedding_provider)
        self.pattern_repo = PatternRepository(vector_store, embedding_provider)

    def ingest_investigation(
        self,
        state: AgentState,
        reasoning: ReasoningOutput,
        report: FinalReport | None = None,
    ) -> InvestigationMemory:
        """Ingest a completed investigation run into memory, updating all entity sub-repositories."""
        now = datetime.now(UTC).isoformat()
        parsed = state.parsed_email

        email_id = parsed.header.message_id if parsed else "unknown_email"
        subject = parsed.header.subject if parsed else "No Subject"
        sender = parsed.header.sender if parsed else "unknown@domain.com"
        executed_tools = tuple(state.tool_results.keys())

        summary_text = report.summary if report else reasoning.summary

        # 1. Ingest Investigation Memory
        inv_record = InvestigationMemory(
            email_id=email_id,
            subject=subject,
            sender=sender,
            classification=report.classification if report else reasoning.risk_level,
            risk_level=reasoning.risk_level,
            executed_tools=executed_tools,
            summary=summary_text,
            confidence_score=reasoning.confidence,
            created_at=now,
            updated_at=now,
        )
        saved_inv = self.investigation_repo.save_investigation(inv_record)

        # 2. Ingest Evidence Memories
        for ev in state.evidence.items:
            ev_record = EvidenceMemory(
                evidence_id=ev.evidence_id,
                category=ev.category,
                title=ev.title,
                description=ev.description,
                severity=ev.severity.value,
                source_tool=ev.source,
                confidence_score=ev.confidence or reasoning.confidence,
                created_at=now,
                updated_at=now,
            )
            self.evidence_repo.save_evidence(ev_record)

            # If evidence is high or critical threat, save ThreatMemory
            if ev.severity.value in ("high", "critical"):
                threat_rec = ThreatMemory(
                    threat_type=ev.category,
                    indicator=ev.title,
                    description=ev.description,
                    associated_campaign=f"campaign_{ev.category}",
                    confidence_score=ev.confidence or reasoning.confidence,
                    created_at=now,
                    updated_at=now,
                )
                self.threat_repo.save_threat(threat_rec)

        # 3. Ingest Sender Memory
        if parsed and parsed.header.sender:
            domain = (
                parsed.header.sender.split("@")[-1]
                if "@" in parsed.header.sender
                else "unknown"
            )
            is_malicious = reasoning.risk_level in ("high", "critical")
            rep_score = 0.1 if is_malicious else 0.9

            sender_rec = SenderMemory(
                sender_email=parsed.header.sender,
                domain=domain,
                reputation_score=rep_score,
                incident_count=1 if is_malicious else 0,
                is_known_spoof=is_malicious,
                confidence_score=reasoning.confidence,
                created_at=now,
                updated_at=now,
            )
            self.sender_repo.save_sender(sender_rec)

        # 4. Ingest URL Memories
        url_res = state.tool_results.get("url_tool")
        if url_res and url_res.metadata:
            extracted = url_res.metadata.get("urls", [])
            for u_item in extracted:
                url_str = u_item if isinstance(u_item, str) else u_item.get("url", "")
                if url_str:
                    domain_str = (
                        url_str.split("//")[-1].split("/")[0]
                        if "//" in url_str
                        else "unknown"
                    )
                    url_rec = URLMemory(
                        url=url_str,
                        domain=domain_str,
                        is_shortened="bit.ly" in domain_str or "tinyurl" in domain_str,
                        is_malicious=reasoning.risk_level in ("high", "critical"),
                        threat_category="phishing"
                        if reasoning.risk_level in ("high", "critical")
                        else None,
                        confidence_score=reasoning.confidence,
                        created_at=now,
                        updated_at=now,
                    )
                    self.url_repo.save_url(url_rec)

        # 5. Ingest Attachment Memories
        if parsed and parsed.attachments:
            for att in parsed.attachments:
                ext = att.filename.split(".")[-1] if "." in att.filename else ""
                att_rec = AttachmentMemory(
                    filename=att.filename,
                    extension=ext,
                    file_hash=None,
                    is_malicious=reasoning.risk_level in ("high", "critical")
                    and ext.lower() in ("exe", "zip", "scr", "vbs"),
                    signature=f"sig_{ext}",
                    confidence_score=reasoning.confidence,
                    created_at=now,
                    updated_at=now,
                )
                self.attachment_repo.save_attachment(att_rec)

        # 6. Ingest Pattern Memory
        for corr in reasoning.evidence_correlation:
            ind_name = str(corr.get("indicator", "unknown_indicator"))
            pattern_rec = PatternMemory(
                pattern_name=ind_name,
                pattern_rules={
                    "severity": reasoning.risk_level,
                    "detail": str(corr.get("detail", "")),
                },
                weight=1.5 if reasoning.risk_level == "critical" else 1.0,
                occurrence_count=1,
                confidence_score=reasoning.confidence,
                created_at=now,
                updated_at=now,
            )
            self.pattern_repo.save_pattern(pattern_rec)

        return saved_inv
