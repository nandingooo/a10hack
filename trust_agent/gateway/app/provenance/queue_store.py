"""QueueStore: the MVP provenance store (AGENTS.md sections 5, 8, 14).

Per-session append-only in-memory queue. Aggregation is a **whole-session
union**: any untrusted / secret / bait entry seen anywhere in the session is
considered reachable from the current action. Simple and safe (it never
forgets a poisoned read); the accepted trade-off is over-blocking on unrelated
actions, which the TreeStore fixes later behind the same interface.
"""
from __future__ import annotations

from collections import defaultdict

from .store import Aggregate, ContextEntry, ProvenanceStore
from .tags import Sensitivity, Trust


class QueueStore(ProvenanceStore):
    def __init__(self) -> None:
        self._by_session: dict[str, list[ContextEntry]] = defaultdict(list)

    def append(self, entry: ContextEntry) -> str:
        # Invariants 3 & 4: append-only; never mutated or evicted.
        self._by_session[entry.session_id].append(entry)
        return entry.id

    def get_entries(self, session_id: str) -> list[ContextEntry]:
        return list(self._by_session.get(session_id, []))

    def aggregate(self, session_id: str, action_entry: ContextEntry) -> Aggregate:
        agg = Aggregate()
        supporting: list[str] = []
        confidences: list[float] = []
        for e in self._by_session.get(session_id, []):
            lbl = e.labels
            contributed = False
            if lbl.effective_trust == Trust.UNTRUSTED:
                agg.reached_untrusted = True
                contributed = True
            if lbl.sensitivity == Sensitivity.SECRET:
                agg.reached_secret = True
                contributed = True
            if lbl.bait:
                agg.reached_bait = True
                contributed = True
            if contributed:
                supporting.append(e.id)
                confidences.append(lbl.confidence)
        agg.supporting_entry_ids = supporting
        # Weakest-hop in spirit; always 1.0 in the MVP (confidence is set in the tree phase).
        agg.confidence = min(confidences) if confidences else 1.0
        return agg
