from __future__ import annotations

import json
import pytest
from pydantic import ValidationError

from src.analyzers.agent.evidence import EvidenceAggregator, EvidenceBuilder
from src.models.agent import ToolEvidence
from src.models.evidence import Evidence, EvidenceCollection, EvidenceSeverity


def test_evidence_model_defaults_and_immutability() -> None:
    ev = Evidence(
        title="Test Title",
        description="Test Description",
        severity=EvidenceSeverity.HIGH,
        source="test_source",
    )

    assert ev.evidence_id.startswith("ev_")
    assert ev.title == "Test Title"
    assert ev.severity is EvidenceSeverity.HIGH
    assert ev.category == "general"
    assert ev.timestamp != ""

    with pytest.raises((TypeError, ValidationError)):
        ev.title = "New Title"  # type: ignore[misc]


def test_evidence_json_and_dict_serialization() -> None:
    ev = EvidenceBuilder.create()\
        .with_source("sender_tool")\
        .with_category("authentication")\
        .with_severity(EvidenceSeverity.CRITICAL)\
        .with_confidence(0.99)\
        .with_title("SPF Spoofing")\
        .with_description("SPF record failed for sending domain")\
        .with_recommendation("Block email sender domain")\
        .with_metadata({"domain": "phish.example"})\
        .build()

    dict_data = ev.to_dict()
    assert dict_data["source"] == "sender_tool"
    assert dict_data["confidence"] == 0.99
    assert dict_data["recommendation"] == "Block email sender domain"

    reconstructed = Evidence.from_dict(dict_data)
    assert reconstructed == ev

    json_str = ev.to_json()
    assert "SPF Spoofing" in json_str
    reconstructed_json = Evidence.from_json(json_str)
    assert reconstructed_json == ev


def test_evidence_collection_filtering_and_immutability() -> None:
    ev1 = Evidence(
        source="url_tool",
        category="suspicious_link",
        title="Phishing URL",
        description="Found phishing domain",
        severity=EvidenceSeverity.CRITICAL,
    )
    ev2 = Evidence(
        source="sender_tool",
        category="authentication",
        title="DKIM Pass",
        description="DKIM signature verified",
        severity=EvidenceSeverity.INFO,
    )

    collection = EvidenceCollection(items=(ev1, ev2))

    assert len(collection.items) == 2

    critical_items = collection.filter_by_severity(EvidenceSeverity.CRITICAL)
    assert len(critical_items) == 1
    assert critical_items[0] == ev1

    sender_items = collection.filter_by_source("sender_tool")
    assert len(sender_items) == 1
    assert sender_items[0] == ev2

    url_category_items = collection.filter_by_category("suspicious_link")
    assert len(url_category_items) == 1
    assert url_category_items[0] == ev1

    # Test adding items returns new collection
    ev3 = Evidence(
        source="attachment_tool",
        category="macro",
        title="VBA Macro",
        description="Office doc contains macro",
        severity=EvidenceSeverity.HIGH,
    )
    new_collection = collection.add(ev3)
    assert len(collection.items) == 2
    assert len(new_collection.items) == 3


def test_evidence_builder_fluent_api() -> None:
    builder = (
        EvidenceBuilder.create()
        .with_source("attachment_tool")
        .with_category("archive")
        .with_severity("CRITICAL")
        .with_confidence(0.95)
        .with_title("Zip Bomb Detected")
        .with_description("Zip file has >100x compression ratio")
        .with_recommendation("Quarantine attachment")
        .add_metadata("compression_ratio", 120.5)
    )

    ev = builder.build()
    assert ev.source == "attachment_tool"
    assert ev.category == "archive"
    assert ev.severity is EvidenceSeverity.CRITICAL
    assert ev.confidence == 0.95
    assert ev.recommendation == "Quarantine attachment"
    assert ev.metadata["compression_ratio"] == 120.5


def test_evidence_aggregator_deduplication_and_sorting() -> None:
    ev_critical = Evidence(
        source="attachment_tool",
        category="executable",
        title="PE Binary",
        description="Disguised executable",
        severity=EvidenceSeverity.CRITICAL,
    )
    ev_high = Evidence(
        source="url_tool",
        category="suspicious_pattern",
        title="Typosquat Domain",
        description="Domain mimics popular brand",
        severity=EvidenceSeverity.HIGH,
    )
    ev_duplicate = Evidence(
        source="url_tool",
        category="suspicious_pattern",
        title="Typosquat Domain",
        description="Domain mimics popular brand",
        severity=EvidenceSeverity.HIGH,
    )
    tool_ev = ToolEvidence(
        category="sender_header",
        detail="From and Sender headers mismatch",
        metadata={"severity": "medium"},
    )

    items = [ev_high, ev_critical, ev_duplicate, tool_ev]
    aggregated = EvidenceAggregator.aggregate(items, default_source="sender_tool")

    # Should deduplicate duplicate item (3 unique items remaining)
    assert len(aggregated.items) == 3

    # Sorted by severity (CRITICAL first, then HIGH, then MEDIUM)
    assert aggregated.items[0].severity is EvidenceSeverity.CRITICAL
    assert aggregated.items[1].severity is EvidenceSeverity.HIGH
    assert aggregated.items[2].severity is EvidenceSeverity.MEDIUM
