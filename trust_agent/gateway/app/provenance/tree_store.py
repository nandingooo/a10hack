"""TreeStore: the post-MVP provenance store (AGENTS.md section 14).

Same ``ProvenanceStore`` interface as ``QueueStore``. Differences when built:
  - ``append()`` also populates ``ContextEntry.parents`` via edge heuristics
    (content overlap 0.9, file lineage 0.8, recency 0.4).
  - ``aggregate()`` becomes ``trace_back()``: a BFS over ``parents`` from the
    action, collecting reached tags + weakest-hop confidence + the path as
    ``supporting_entry_ids``.

Swapping this in for ``QueueStore`` requires NO change to the guard or the
decision rules. Stubbed now so the interface is provably ready for the upgrade.
"""
from __future__ import annotations

from .store import Aggregate, ContextEntry, ProvenanceStore


class TreeStore(ProvenanceStore):  # pragma: no cover - implemented in the queue->tree upgrade
    def __init__(self) -> None:
        self._by_session: dict[str, list[ContextEntry]] = {}

    def append(self, entry: ContextEntry) -> str:
        raise NotImplementedError(
            "TreeStore lands in the queue->tree upgrade (AGENTS.md 14)"
        )

    def aggregate(self, session_id: str, action_entry: ContextEntry) -> Aggregate:
        raise NotImplementedError(
            "trace_back() lands in the queue->tree upgrade (AGENTS.md 14)"
        )

    def get_entries(self, session_id: str) -> list[ContextEntry]:
        raise NotImplementedError
