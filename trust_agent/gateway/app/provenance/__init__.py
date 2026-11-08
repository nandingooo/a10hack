"""AgentAirlock provenance module: tag model + store + aggregation.

Owns the tagging of each activity and how tags are stored and aggregated.
MVP uses the QueueStore; the TreeStore drops in later behind the same
ProvenanceStore interface (AGENTS.md sections 5-8, 14).
"""
from .tags import Labels, Sensitivity, Trust
from .store import (
    ActionProps, Aggregate, Channel, ContextEntry, Kind, Op,
    ProvenanceStore, Session, SINK_OPS,
)
from .queue_store import QueueStore
from .graph_store import GraphStore
from .labeler import Labeler, Policy, match
from .multiagent import (
    AGENT_ORIGIN_PREFIX, SHARED_ORIGIN_PREFIX, INBOUND_CONFIDENCE,
    derive_inbound_labels, is_cross_agent_origin, new_entry_id,
)

__all__ = [
    "Labels", "Sensitivity", "Trust",
    "ActionProps", "Aggregate", "Channel", "ContextEntry", "Kind", "Op",
    "ProvenanceStore", "Session", "SINK_OPS",
    "QueueStore", "GraphStore", "Labeler", "Policy", "match",
    "AGENT_ORIGIN_PREFIX", "SHARED_ORIGIN_PREFIX", "INBOUND_CONFIDENCE",
    "derive_inbound_labels", "is_cross_agent_origin", "new_entry_id",
]
