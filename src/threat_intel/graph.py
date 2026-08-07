"""IOC Relationship Graph abstraction for graph database (Neo4j) preparation and threat correlation."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from src.common.models import BaseDTO


class IOCNodeDTO(BaseDTO):
    """Represent one vertex (IOC node) in the relationship graph."""

    node_id: str = Field(description="Unique node identifier (type:value)")
    target_type: str = Field(description="ip, domain, url, hash, email, header")
    value: str = Field(description="Raw indicator value")
    properties: dict[str, Any] = Field(
        default_factory=dict, description="Node attributes"
    )


class IOCEdgeDTO(BaseDTO):
    """Represent one directed edge connecting two IOC nodes."""

    source_id: str = Field(description="Source node_id")
    target_id: str = Field(description="Target node_id")
    relationship_type: str = Field(
        description="RESOLVES_TO, HOSTED_ON, DELIVERS_PAYLOAD, SENDER_OF, etc."
    )
    properties: dict[str, Any] = Field(
        default_factory=dict, description="Edge metadata"
    )


class IOCRelationshipGraph:
    """In-memory directed relationship graph mapping connections between email IOCs."""

    def __init__(self) -> None:
        self.nodes: dict[str, IOCNodeDTO] = {}
        self.edges: list[IOCEdgeDTO] = []

    def add_node(
        self, target_type: str, value: str, properties: dict[str, Any] | None = None
    ) -> str:
        """Add node to graph, returning unique node_id."""
        if not value or not value.strip():
            return ""

        node_id = f"{target_type.lower()}:{value.strip().lower()}"
        if node_id not in self.nodes:
            self.nodes[node_id] = IOCNodeDTO(
                node_id=node_id,
                target_type=target_type.lower(),
                value=value.strip(),
                properties=properties or {},
            )
        return node_id

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship_type: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Add directed edge between source and target nodes."""
        if not source_id or not target_id:
            return

        edge = IOCEdgeDTO(
            source_id=source_id,
            target_id=target_id,
            relationship_type=relationship_type.upper(),
            properties=properties or {},
        )
        self.edges.append(edge)

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph representation into dictionary payload."""
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [n.model_dump() for n in self.nodes.values()],
            "edges": [e.model_dump() for e in self.edges],
        }
