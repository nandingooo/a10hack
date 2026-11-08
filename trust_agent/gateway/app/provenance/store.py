"""Provenance records + storage interface (AGENTS.md sections 6, 8).

``ProvenanceStore`` is the abstraction that keeps the guard identical whether
we use the queue (MVP) or the tree (later) — only the injected implementation
changes. ``Aggregate`` is the stable contract consumed by P1's ``decide()``.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .tags import Labels


class Kind(str, Enum):
    SOURCE = "source"
    SECRET = "secret"   # a read of a secret-labeled resource
    READ_RESULT = "read_result"
    ACTION = "action"


class Channel(str, Enum):
    HOOK = "hook"
    EGRESS = "egress"
    MCP = "mcp"
    MODEL = "model"


class Op(str, Enum):
    READ_FILE = "ReadFile"
    WRITE_FILE = "WriteFile"
    DELETE_FILE = "DeleteFile"
    RUN_COMMAND = "RunCommand"
    NETWORK_REQUEST = "NetworkRequest"
    CALL_TOOL = "CallTool"
    MODEL_CALL = "ModelCall"


# Ops that can cause harm — decisions happen at these ("sinks").
SINK_OPS = {
    Op.RUN_COMMAND, Op.NETWORK_REQUEST, Op.CALL_TOOL,
    Op.WRITE_FILE, Op.DELETE_FILE,
}


@dataclass(frozen=True)
class ActionProps:
    is_exit: bool = False
    is_destructive: bool = False


@dataclass
class ContextEntry:
    """One record of something the agent read or did (AGENTS.md 6.1)."""
    id: str
    ts: float
    session_id: str
    kind: Kind
    channel: Channel
    op: Op
    target: str
    origin: str
    labels: Labels
    action_props: Optional[ActionProps] = None
    verdict: Optional[str] = None   # written by the guard after a decision
    rule: Optional[str] = None
    # MVP: always []. Tree phase: parent entry ids. This field is the single
    # hook that makes the queue->tree upgrade cheap (AGENTS.md 14).
    parents: list[str] = field(default_factory=list)

    @property
    def is_action(self) -> bool:
        return self.kind == Kind.ACTION


@dataclass
class Session:
    session_id: str
    agent: str = "claude-code"
    role: str = "developer"
    status: str = "ACTIVE"   # ACTIVE | KILLED
    token: str = ""
    created_at: float = 0.0


@dataclass
class Aggregate:
    """What dangerous tags are reachable from an action. The stable contract
    between this module and P1's decision rules."""
    reached_untrusted: bool = False
    reached_secret: bool = False
    reached_bait: bool = False
    confidence: float = 1.0
    supporting_entry_ids: list[str] = field(default_factory=list)  # powers the "why"


class ProvenanceStore(ABC):
    """Guard-facing interface. QueueStore (MVP) and TreeStore (later) both
    implement this; the guard never knows which it is using."""

    @abstractmethod
    def append(self, entry: ContextEntry) -> str:
        """Record an activity. Returns the entry id. Append-only."""

    @abstractmethod
    def aggregate(self, session_id: str, action_entry: ContextEntry) -> Aggregate:
        """Return the dangerous tags reachable from ``action_entry``."""

    @abstractmethod
    def get_entries(self, session_id: str) -> list[ContextEntry]:
        """All recorded entries for a session (for audit / dashboard)."""

    def get_entry(self, session_id: str, entry_id: str) -> ContextEntry | None:
        return next((entry for entry in self.get_entries(session_id) if entry.id == entry_id), None)
