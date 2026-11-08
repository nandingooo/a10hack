"""Multi-agent / inter-agent provenance (DESIGN + STUBS).

Single-agent sessions are isolated in QueueStore (agent A's untrusted read must
not ambiently taint agent B). But when agents *communicate* -- a team-channel
message, a shared task-board entry, a shared git-worktree file, or a delegation
that forks context -- that is a real data-flow edge between sessions. Without
modelling it we miss cross-agent laundering:

    A reads a secret -> messages B -> B exfiltrates.   (B "never touched" it.)

This module provides the pieces needed to treat inter-agent communication as a
provenance edge. The full cross-session graph is the tree phase (see
docs/monitoring-and-multiagent.md); here we ship the primitives + stubs so the
queue MVP stays simple and the upgrade is wired.
"""
from __future__ import annotations

from .store import Aggregate
from .tags import Labels, Sensitivity, Trust

# Inbound origins whose trust is DERIVED from the sender, not static policy.
AGENT_ORIGIN_PREFIX = "agent:"     # e.g. "agent:claude-7f3a" -> a message/delegation from that agent
SHARED_ORIGIN_PREFIX = "shared:"   # e.g. "shared:taskboard" / "shared:worktree" -> a shared conduit

# Cross-agent edges are inferred (we don't see the exact bytes that moved), so
# they carry less-than-certain confidence; a low-confidence dangerous flow should
# route to "ask a human" rather than a hard block.
INBOUND_CONFIDENCE = 0.8


def is_cross_agent_origin(origin: str) -> bool:
    """True if this activity's data came from another agent or a shared conduit."""
    return origin.startswith(AGENT_ORIGIN_PREFIX) or origin.startswith(SHARED_ORIGIN_PREFIX)


def new_entry_id(session_id: str, seq: int) -> str:
    """Globally-unique entry id (session-prefixed) so the tree phase can draw
    ``parents`` edges ACROSS sessions, not just within one."""
    return f"{session_id}:e{seq}"


def derive_inbound_labels(sender: Aggregate, confidence: float = INBOUND_CONFIDENCE) -> Labels:
    """Label an inter-agent message / shared-resource read by inheriting the
    sender's worst taint at send time. This is the 'taint-on-ingest' rule that
    makes cross-agent laundering visible.

    Queue MVP: the caller looks up the sender's ``aggregate()`` and passes it in.
    Tree phase: this becomes an edge from the receiver's entry to the sender's
    contributing entries (true cross-session provenance), and ``confidence``
    becomes the weakest hop along that edge.
    """
    return Labels(
        trust=Trust.UNTRUSTED if sender.reached_untrusted else Trust.TRUSTED,
        sensitivity=Sensitivity.SECRET if sender.reached_secret else Sensitivity.PUBLIC,
        bait=sender.reached_bait,
        in_workspace=True,
        confidence=confidence,
    )
