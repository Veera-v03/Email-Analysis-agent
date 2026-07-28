"""Graph-ready data contracts for sender identity relationships."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

from src.models.sender import MAX_RAW_ADDRESS_LENGTH

GRAPH_NODE_ID_LENGTH = 24


class SenderRelationshipNodeType(StrEnum):
    """Identify a node's role in the sender relationship chain."""

    DISPLAY_NAME = "display_name"
    FROM = "from"
    SENDER = "sender"
    REPLY_TO = "reply_to"
    RETURN_PATH = "return_path"


class SenderRelationshipEdgeType(StrEnum):
    """Identify a directed relationship in the sender relationship chain."""

    DISPLAY_NAME_TO_FROM = "display_name_to_from"
    FROM_TO_SENDER = "from_to_sender"
    SENDER_TO_REPLY_TO = "sender_to_reply_to"
    REPLY_TO_TO_RETURN_PATH = "reply_to_to_return_path"


class SenderRelationshipNode(BaseModel):
    """Represent one provenance-preserving graph node for sender analysis."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    node_id: StrictStr = Field(min_length=1, max_length=128)
    node_type: SenderRelationshipNodeType
    value: StrictStr = Field(min_length=1, max_length=MAX_RAW_ADDRESS_LENGTH)
    is_syntactically_valid: StrictBool


class SenderRelationshipEdge(BaseModel):
    """Represent a directed, typed edge between sender relationship nodes."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    source_node_id: StrictStr = Field(min_length=1, max_length=128)
    target_node_id: StrictStr = Field(min_length=1, max_length=128)
    edge_type: SenderRelationshipEdgeType


class SenderRelationshipGraph(BaseModel):
    """Contain graph-ready sender identity nodes and their typed relationships."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    nodes: tuple[SenderRelationshipNode, ...] = Field(default=())
    edges: tuple[SenderRelationshipEdge, ...] = Field(default=())
