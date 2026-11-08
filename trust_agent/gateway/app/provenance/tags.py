"""Tag model for AgentAirlock provenance (AGENTS.md section 5).

Two orthogonal axes (trust + sensitivity) + flags + confidence. Typed for
safety, with an ``as_tagset()`` view so aggregation is a plain set-union and
new tag dimensions can be added later without touching aggregation logic.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Trust(str, Enum):
    """Integrity axis: can this carry instructions we should obey?"""
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"  # Invariant 2: always treated as untrusted downstream


class Sensitivity(str, Enum):
    """Confidentiality axis: how bad if this leaks?"""
    PUBLIC = "public"
    SENSITIVE = "sensitive"
    SECRET = "secret"


Tag = tuple[str, str]  # (dimension, value)


@dataclass(frozen=True)
class Labels:
    """The tags attached to one activity. Frozen: never mutated after creation."""
    trust: Trust
    sensitivity: Sensitivity
    bait: bool = False
    in_workspace: bool = True
    confidence: float = 1.0  # 1.0 in the queue MVP; weakest-hop in the tree phase

    @property
    def effective_trust(self) -> Trust:
        """Fail closed: unknown origin counts as untrusted (Invariant 2)."""
        return Trust.UNTRUSTED if self.trust == Trust.UNKNOWN else self.trust

    def as_tagset(self) -> set[Tag]:
        """Set view used by aggregation. New dimensions can be added here
        without changing any aggregation code."""
        tags: set[Tag] = {
            ("trust", self.effective_trust.value),
            ("sensitivity", self.sensitivity.value),
        }
        if self.bait:
            tags.add(("flag", "bait"))
        if self.in_workspace:
            tags.add(("flag", "in_workspace"))
        return tags
