"""GraphStore: provenance as a DAG, built in real time (the graph upgrade).

Same ``ProvenanceStore`` interface as ``QueueStore`` -- drop-in. The difference
is how a decision is made:

- ``QueueStore.aggregate`` = whole-session union ("did anything untrusted/secret
  appear anywhere in this session?"). Simple, but over-blocks.
- ``GraphStore.aggregate`` = ``trace_back`` ("is this action actually REACHABLE
  from untrusted/secret data?"). Blocks only when poison really flowed into the
  action, and catches laundering through intermediate files.

Edges are drawn incrementally as each entry is appended (real-time construction):
- **file lineage** (conf 0.8): reading a file a prior in-session write produced.
- **recency** (conf 0.4): an action inherits the source reads that fed it
  (the reads since the previous action -- the agent's current working set).

It's a DAG, not a tree: an action can have several parents and a source can
feed several actions. Entry ids are globally unique so edges can later span
sessions (cross-agent provenance).
"""
from __future__ import annotations

import time
from collections import defaultdict

from .multiagent import INBOUND_CONFIDENCE, derive_inbound_labels
from .store import Aggregate, Channel, ContextEntry, Kind, Op, ProvenanceStore
from .tags import Sensitivity, Trust


def _norm(p: str) -> str:
    return (p or "").replace("\\", "/").lower()


class GraphStore(ProvenanceStore):
    def __init__(self, recency_window: int = 12) -> None:
        self._by_session: dict[str, list[ContextEntry]] = defaultdict(list)
        self._index: dict[str, ContextEntry] = {}               # global: id -> entry
        self._conf: dict[str, dict[str, float]] = {}            # child id -> {parent id: confidence}
        # GLOBAL path -> writer id: enables cross-agent shared-file lineage
        # (agent A writes a file, agent B reads it -> B links back to A's write).
        self._producer: dict[str, str] = {}
        self._working: dict[str, list[str]] = defaultdict(list)        # session -> source ids since last action
        self._ingest_seq = 0
        self.recency_window = recency_window

    def append(self, entry: ContextEntry) -> str:
        sess = entry.session_id
        parents: dict[str, float] = {}
        if entry.is_action:
            # the action inherits the reads that fed it (recency)
            for sid in self._working[sess][-self.recency_window:]:
                parents[sid] = max(parents.get(sid, 0.0), 0.4)
            # a written file descends from those reads; future reads of it inherit (lineage)
            if entry.op == Op.WRITE_FILE and entry.target:
                self._producer[_norm(entry.target)] = entry.id   # global: shared files link across agents
            self._working[sess] = []                 # the turn consumed the working set
        else:
            # a read: if this path was produced (by any agent), link to its writer (lineage)
            producer_id = self._producer.get(_norm(entry.target))
            if producer_id and producer_id != entry.id:
                parents[producer_id] = 0.8
            self._working[sess].append(entry.id)

        entry.parents = list(parents.keys())
        self._conf[entry.id] = parents
        self._by_session[sess].append(entry)
        self._index[entry.id] = entry
        return entry.id

    def get_entries(self, session_id: str) -> list[ContextEntry]:
        return list(self._by_session.get(session_id, []))

    def aggregate(self, session_id: str, action_entry: ContextEntry) -> Aggregate:
        """trace_back: BFS over `parents` from the action, collecting the tags
        actually reachable from it + the weakest-hop confidence + the path."""
        agg = Aggregate()
        supporting: list[str] = []
        weakest = 1.0
        seen: set[str] = set()
        # start from what flowed INTO the action (its parents), not the action's own origin
        stack: list[tuple[str, float]] = [
            (pid, self._conf.get(action_entry.id, {}).get(pid, 1.0))
            for pid in action_entry.parents
        ]
        while stack:
            nid, path_conf = stack.pop()
            if nid in seen:
                continue
            seen.add(nid)
            e = self._index.get(nid)
            if e is None:
                continue
            lbl = e.labels
            hit = False
            if lbl.effective_trust == Trust.UNTRUSTED:
                agg.reached_untrusted = True
                hit = True
            if lbl.sensitivity == Sensitivity.SECRET:
                agg.reached_secret = True
                hit = True
            if lbl.bait:
                agg.reached_bait = True
                hit = True
            if hit:
                supporting.append(nid)
                weakest = min(weakest, path_conf)
            for pid in e.parents:
                c = self._conf.get(nid, {}).get(pid, 1.0)
                stack.append((pid, min(path_conf, c)))
        agg.supporting_entry_ids = supporting
        agg.confidence = weakest if supporting else 1.0
        return agg

    # ---- multi-agent / inter-agent provenance ----

    def session_taint(self, session_id: str) -> Aggregate:
        """The sender's worst taint so far (union over its entries). Used to
        label what another agent receives from it."""
        agg = Aggregate()
        sup: list[str] = []
        for e in self.get_entries(session_id):
            lbl = e.labels
            hit = False
            if lbl.effective_trust == Trust.UNTRUSTED:
                agg.reached_untrusted = True
                hit = True
            if lbl.sensitivity == Sensitivity.SECRET:
                agg.reached_secret = True
                hit = True
            if lbl.bait:
                agg.reached_bait = True
                hit = True
            if hit:
                sup.append(e.id)
        agg.supporting_entry_ids = sup
        return agg

    def ingest_inbound(self, receiver_session: str, sender_session: str) -> ContextEntry:
        """Record that ``receiver_session`` received a message / delegation /
        shared artifact from ``sender_session``. The inbound entry inherits the
        sender's taint (taint-on-ingest) and links back to the sender's
        contributing entries (cross-session edges), so the receiver's next
        action traces to the original source. This is how cross-agent laundering
        (A reads a secret -> messages B -> B exfiltrates) is caught."""
        taint = self.session_taint(sender_session)
        labels = derive_inbound_labels(taint)
        self._ingest_seq += 1
        eid = f"{receiver_session}:m{self._ingest_seq}"
        parents = {pid: INBOUND_CONFIDENCE for pid in taint.supporting_entry_ids}
        entry = ContextEntry(
            id=eid, ts=time.time(), session_id=receiver_session, kind=Kind.SOURCE,
            channel=Channel.MCP, op=Op.CALL_TOOL, target=f"agent:{sender_session}",
            origin=f"agent:{sender_session}", labels=labels,
        )
        entry.parents = list(parents.keys())
        self._conf[eid] = parents
        self._by_session[receiver_session].append(entry)
        self._index[eid] = entry
        self._working[receiver_session].append(eid)  # the receiver's next action inherits this
        return entry
