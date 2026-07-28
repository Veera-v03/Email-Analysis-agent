"""Unit tests for independent evidence collection."""

from __future__ import annotations

from src.models.evidence import Evidence, EvidenceSeverity
from src.utils.evidence import EvidenceCollector, EvidenceEmitter, EvidenceSink


def test_collector_emits_complete_structured_evidence() -> None:
    """A collector creates evidence with every required independent field."""
    collector = EvidenceCollector()

    evidence = collector.emit(
        evidence_type="domain.keyword_match",
        title="Configured domain keyword observed",
        description="The configured keyword occurred in the parsed domain.",
        severity=EvidenceSeverity.LOW,
        source="domain_feature_analyzer",
        metadata={"keywords": ["secure"], "domain": "secure.example"},
    )

    assert evidence.evidence_id.startswith("evidence:")
    assert evidence.evidence_type == "domain.keyword_match"
    assert evidence.severity is EvidenceSeverity.LOW
    assert evidence.metadata["keywords"] == ["secure"]
    assert collector.snapshot().items == (evidence,)


def test_evidence_records_remain_source_independent() -> None:
    """Different analyzers can emit records without importing one another."""
    collector = EvidenceCollector()
    first = collector.emit(
        evidence_type="sender.header_missing",
        title="Sender header absent",
        description="The Sender header was not present.",
        severity=EvidenceSeverity.INFO,
        source="sender_header_comparator",
    )
    second = collector.emit(
        evidence_type="authentication.conflict",
        title="Conflicting DMARC claims",
        description="Multiple Authentication-Results headers disagreed.",
        severity=EvidenceSeverity.MEDIUM,
        source="authentication_header_interpreter",
    )

    evidence = collector.snapshot().items
    assert evidence == (first, second)
    assert first.source != second.source
    assert first.evidence_id != second.evidence_id


def test_collector_accepts_independently_created_evidence() -> None:
    """The sink interface permits a component to supply its own evidence record."""
    collector = EvidenceCollector()
    external_evidence = Evidence(
        evidence_id="external:001",
        evidence_type="display_name.organization_reference",
        title="Organization term observed",
        description="A configured organization term occurred in the display name.",
        severity=EvidenceSeverity.INFO,
        source="display_name_analyzer",
        metadata={"organization": "example"},
    )

    collector.record(external_evidence)

    assert collector.snapshot().items == (external_evidence,)
    assert isinstance(collector, EvidenceSink)


def test_evidence_schema_contains_no_probability_or_score_field() -> None:
    """Evidence is intentionally independent from future risk-scoring concerns."""
    evidence = EvidenceCollector().emit(
        evidence_type="authentication.spf",
        title="SPF header claim observed",
        description="An SPF status claim was present in Authentication-Results.",
        severity=EvidenceSeverity.INFO,
        source="authentication_header_interpreter",
    )

    serialized = evidence.model_dump()
    assert "phishing_probability" not in serialized
    assert "risk_score" not in serialized


def test_emitter_protocol_is_structurally_available_to_analyzers() -> None:
    """Analyzer implementations can depend on the emission protocol only."""

    class ExampleEmitter:
        """Minimal structural implementation for protocol verification."""

        def emit_evidence(self, sink: EvidenceSink) -> None:
            """Emit one record through the abstract evidence sink."""
            sink.record(
                Evidence(
                    evidence_id="example:001",
                    evidence_type="example.observation",
                    title="Example observation",
                    description="Protocol conformance test evidence.",
                    severity=EvidenceSeverity.INFO,
                    source="example_emitter",
                )
            )

    emitter = ExampleEmitter()
    assert isinstance(emitter, EvidenceEmitter)
