"""Unit tests for sender relationship graph preparation."""

from __future__ import annotations

from src.analyzers.sender.relationships import DeterministicSenderRelationshipBuilder
from src.models.sender import ParsedEmailAddress, SenderAnalysisResult
from src.models.sender_relationship import (
    SenderRelationshipEdgeType,
    SenderRelationshipNodeType,
)


def _address(email: str, display_name: str | None = None) -> ParsedEmailAddress:
    """Create parsed sender address evidence for graph-builder tests."""
    username, domain = email.split("@")
    return ParsedEmailAddress(
        raw_value=email,
        display_name=display_name,
        email=email,
        username=username,
        domain=domain,
        is_syntactically_valid=True,
    )


def test_builds_requested_relationship_chain_with_graph_ready_records() -> None:
    """The builder produces typed nodes and edges for each present chain stage."""
    sender_data = SenderAnalysisResult(
        from_addresses=(_address("notice@example.com", "Account Security"),),
        sender_addresses=(_address("mailer@example.com"),),
        reply_to_addresses=(_address("help@example.com"),),
        return_path_addresses=(_address("bounce@example.com"),),
    )

    graph = DeterministicSenderRelationshipBuilder().build(sender_data)

    assert {node.node_type for node in graph.nodes} == {
        SenderRelationshipNodeType.DISPLAY_NAME,
        SenderRelationshipNodeType.FROM,
        SenderRelationshipNodeType.SENDER,
        SenderRelationshipNodeType.REPLY_TO,
        SenderRelationshipNodeType.RETURN_PATH,
    }
    assert {edge.edge_type for edge in graph.edges} == {
        SenderRelationshipEdgeType.DISPLAY_NAME_TO_FROM,
        SenderRelationshipEdgeType.FROM_TO_SENDER,
        SenderRelationshipEdgeType.SENDER_TO_REPLY_TO,
        SenderRelationshipEdgeType.REPLY_TO_TO_RETURN_PATH,
    }
    assert all("@" not in node.node_id for node in graph.nodes)


def test_multiple_header_occurrences_create_all_adjacent_relationship_edges() -> None:
    """Graph preparation preserves multiple values rather than collapsing provenance."""
    sender_data = SenderAnalysisResult(
        from_addresses=(_address("first@example.com"),),
        sender_addresses=(
            _address("first-sender@example.com"),
            _address("second-sender@example.com"),
        ),
        reply_to_addresses=(_address("reply@example.com"),),
    )

    graph = DeterministicSenderRelationshipBuilder().build(sender_data)

    from_to_sender = [
        edge
        for edge in graph.edges
        if edge.edge_type is SenderRelationshipEdgeType.FROM_TO_SENDER
    ]
    sender_to_reply = [
        edge
        for edge in graph.edges
        if edge.edge_type is SenderRelationshipEdgeType.SENDER_TO_REPLY_TO
    ]
    assert len(from_to_sender) == 2
    assert len(sender_to_reply) == 2


def test_missing_intermediate_stage_does_not_create_non_adjacent_edges() -> None:
    """Absent chain stages are retained as absent instead of being bypassed."""
    sender_data = SenderAnalysisResult(
        from_addresses=(_address("sender@example.com"),),
        reply_to_addresses=(_address("reply@example.com"),),
    )

    graph = DeterministicSenderRelationshipBuilder().build(sender_data)

    assert graph.edges == ()


def test_invalid_address_value_remains_a_graph_node() -> None:
    """Malformed input remains visible for downstream consumers without failure."""
    invalid_sender = ParsedEmailAddress(
        raw_value="invalid mailbox",
        is_syntactically_valid=False,
    )
    graph = DeterministicSenderRelationshipBuilder().build(
        SenderAnalysisResult(sender_addresses=(invalid_sender,))
    )

    assert len(graph.nodes) == 1
    assert graph.nodes[0].value == "invalid mailbox"
    assert graph.nodes[0].is_syntactically_valid is False
