"""Graph preparation for sender identity relationships.

This module prepares typed data records only. It does not traverse a graph,
invoke LangGraph, or make any security assessment.
"""

from __future__ import annotations

from hashlib import sha256
from itertools import product
from typing import Protocol, runtime_checkable

from src.models.sender import ParsedEmailAddress, SenderAnalysisResult
from src.models.sender_relationship import (
    GRAPH_NODE_ID_LENGTH,
    SenderRelationshipEdge,
    SenderRelationshipEdgeType,
    SenderRelationshipGraph,
    SenderRelationshipNode,
    SenderRelationshipNodeType,
)

HeaderNodeMap = dict[SenderRelationshipNodeType, tuple[SenderRelationshipNode, ...]]


@runtime_checkable
class SenderRelationshipBuilder(Protocol):
    """Build graph-ready sender relationship records from extracted sender data."""

    def build(self, sender_data: SenderAnalysisResult) -> SenderRelationshipGraph:
        """Build a graph representation without performing graph processing."""


class DeterministicSenderRelationshipBuilder:
    """Build stable nodes and edges for the sender identity relationship chain."""

    def build(self, sender_data: SenderAnalysisResult) -> SenderRelationshipGraph:
        """Build a graph-ready relationship model from parsed sender evidence."""
        address_groups = self._address_groups(sender_data)
        header_nodes = {
            node_type: self._address_nodes(node_type, addresses)
            for node_type, addresses in address_groups.items()
        }
        display_nodes, display_edges = self._display_name_nodes(
            sender_data.from_addresses,
            header_nodes[SenderRelationshipNodeType.FROM],
        )
        chain_edges = self._chain_edges(header_nodes)
        nodes = (
            *display_nodes,
            *(node for nodes in header_nodes.values() for node in nodes),
        )
        return SenderRelationshipGraph(
            nodes=nodes,
            edges=(*display_edges, *chain_edges),
        )

    @staticmethod
    def _address_groups(
        sender_data: SenderAnalysisResult,
    ) -> dict[SenderRelationshipNodeType, tuple[ParsedEmailAddress, ...]]:
        """Map supported sender headers to their extracted address values."""
        return {
            SenderRelationshipNodeType.FROM: sender_data.from_addresses,
            SenderRelationshipNodeType.SENDER: sender_data.sender_addresses,
            SenderRelationshipNodeType.REPLY_TO: sender_data.reply_to_addresses,
            SenderRelationshipNodeType.RETURN_PATH: sender_data.return_path_addresses,
        }

    @staticmethod
    def _address_nodes(
        node_type: SenderRelationshipNodeType,
        addresses: tuple[ParsedEmailAddress, ...],
    ) -> tuple[SenderRelationshipNode, ...]:
        """Create provenance-preserving address nodes for one sender header."""
        return tuple(
            SenderRelationshipNode(
                node_id=DeterministicSenderRelationshipBuilder._node_id(
                    node_type,
                    index,
                    address.email or address.raw_value,
                ),
                node_type=node_type,
                value=address.email or address.raw_value,
                is_syntactically_valid=address.is_syntactically_valid,
            )
            for index, address in enumerate(addresses)
        )

    @staticmethod
    def _display_name_nodes(
        from_addresses: tuple[ParsedEmailAddress, ...],
        from_nodes: tuple[SenderRelationshipNode, ...],
    ) -> tuple[tuple[SenderRelationshipNode, ...], tuple[SenderRelationshipEdge, ...]]:
        """Create display-name nodes and edges for From-address occurrences."""
        display_nodes: list[SenderRelationshipNode] = []
        display_edges: list[SenderRelationshipEdge] = []
        address_node_pairs = zip(from_addresses, from_nodes, strict=True)
        for index, (address, from_node) in enumerate(address_node_pairs):
            if not address.display_name:
                continue
            display_node = SenderRelationshipNode(
                node_id=DeterministicSenderRelationshipBuilder._node_id(
                    SenderRelationshipNodeType.DISPLAY_NAME,
                    index,
                    address.display_name,
                ),
                node_type=SenderRelationshipNodeType.DISPLAY_NAME,
                value=address.display_name,
                is_syntactically_valid=address.is_syntactically_valid,
            )
            display_nodes.append(display_node)
            display_edges.append(
                SenderRelationshipEdge(
                    source_node_id=display_node.node_id,
                    target_node_id=from_node.node_id,
                    edge_type=SenderRelationshipEdgeType.DISPLAY_NAME_TO_FROM,
                )
            )
        return tuple(display_nodes), tuple(display_edges)

    @staticmethod
    def _chain_edges(header_nodes: HeaderNodeMap) -> tuple[SenderRelationshipEdge, ...]:
        """Create adjacent-stage edges only when both stages have occurrences."""
        chain = (
            (
                SenderRelationshipNodeType.FROM,
                SenderRelationshipNodeType.SENDER,
                SenderRelationshipEdgeType.FROM_TO_SENDER,
            ),
            (
                SenderRelationshipNodeType.SENDER,
                SenderRelationshipNodeType.REPLY_TO,
                SenderRelationshipEdgeType.SENDER_TO_REPLY_TO,
            ),
            (
                SenderRelationshipNodeType.REPLY_TO,
                SenderRelationshipNodeType.RETURN_PATH,
                SenderRelationshipEdgeType.REPLY_TO_TO_RETURN_PATH,
            ),
        )
        edges: list[SenderRelationshipEdge] = []
        for source_type, target_type, edge_type in chain:
            edges.extend(
                SenderRelationshipEdge(
                    source_node_id=source_node.node_id,
                    target_node_id=target_node.node_id,
                    edge_type=edge_type,
                )
                for source_node, target_node in product(
                    header_nodes[source_type],
                    header_nodes[target_type],
                )
            )
        return tuple(edges)

    @staticmethod
    def _node_id(
        node_type: SenderRelationshipNodeType,
        index: int,
        value: str,
    ) -> str:
        """Create a stable opaque identifier without exposing a mailbox in the ID."""
        node_material = f"{node_type.value}|{index}|{value}".encode()
        digest = sha256(node_material).hexdigest()[:GRAPH_NODE_ID_LENGTH]
        return f"{node_type.value}:{digest}"
