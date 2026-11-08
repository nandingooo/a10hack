"""SqliteStore: a persistent ProvenanceStore backed by SQLite.

Same interface as QueueStore/GraphStore (drop-in), but durable -- and built to
be compatible with William's gateway store:
  * `sessions(id, status)` with ACTIVE/KILLED,
  * `entries` carries `trust` / `sensitivity` columns (+ our richer labels and
    a parent `edges` table for graph trace_back),
  * `evidence(session)` returns the last untrusted / last secret entry id, the
    same session-level signal William's `decide()` consumes.

So William's decision layer can read `evidence()` off this DB, while our own
`aggregate()` does precise graph `trace_back` over the persisted edges.

Edges are built exactly like GraphStore, but derived from SQL (restart-safe):
  * recency (0.4): an action inherits the source reads since the previous action,
  * file lineage (0.8): reading a file a prior write produced (global -> cross-agent).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .store import Aggregate, ActionProps, Channel, ContextEntry, Kind, Op
from .tags import Labels, Sensitivity, Trust

RECENCY_WINDOW = 12

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','KILLED'))
);
CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    channel TEXT NOT NULL,
    op TEXT NOT NULL,
    target TEXT NOT NULL,
    target_norm TEXT NOT NULL,
    origin TEXT NOT NULL,
    trust TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    bait INTEGER NOT NULL DEFAULT 0,
    in_workspace INTEGER NOT NULL DEFAULT 1,
    confidence REAL NOT NULL DEFAULT 1.0,
    is_exit INTEGER NOT NULL DEFAULT 0,
    is_destructive INTEGER NOT NULL DEFAULT 0,
    verdict TEXT,
    rule TEXT
);
CREATE INDEX IF NOT EXISTS entries_session ON entries(session_id);
CREATE INDEX IF NOT EXISTS entries_producer ON entries(target_norm);
CREATE INDEX IF NOT EXISTS entries_untrusted ON entries(session_id) WHERE trust = 'untrusted';
CREATE INDEX IF NOT EXISTS entries_secret ON entries(session_id) WHERE sensitivity = 'secret';
CREATE TABLE IF NOT EXISTS edges (
    child_id TEXT NOT NULL,
    parent_id TEXT NOT NULL,
    confidence REAL NOT NULL,
    PRIMARY KEY (child_id, parent_id)
);
"""


def _norm(p: str) -> str:
    return (p or "").replace("\\", "/").lower()


class SqliteStore:
    def __init__(self, path: str | Path = "airlock.db") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # one shared connection; serialize writes with a transaction per call
        self._db = sqlite3.connect(self.path, timeout=5, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.executescript(_SCHEMA)
        self._db.commit()

    # ---- ProvenanceStore interface ----

    def append(self, entry: ContextEntry) -> str:
        db = self._db
        with db:  # transaction
            db.execute("INSERT OR IGNORE INTO sessions(id, status) VALUES (?, 'ACTIVE')",
                       (entry.session_id,))
            lbl = entry.labels
            ap = entry.action_props
            db.execute(
                """INSERT OR REPLACE INTO entries
                   (id, session_id, ts, kind, channel, op, target, target_norm, origin,
                    trust, sensitivity, bait, in_workspace, confidence, is_exit, is_destructive, verdict, rule)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (entry.id, entry.session_id, entry.ts, entry.kind.value, entry.channel.value,
                 entry.op.value, entry.target, _norm(entry.target), entry.origin,
                 lbl.effective_trust.value, lbl.sensitivity.value, int(lbl.bait),
                 int(lbl.in_workspace), lbl.confidence,
                 int(bool(ap and ap.is_exit)), int(bool(ap and ap.is_destructive)),
                 entry.verdict, entry.rule),
            )
            rowid = db.execute("SELECT rowid FROM entries WHERE id = ?", (entry.id,)).fetchone()[0]
            parents = self._compute_parents(db, entry, rowid)
            for pid, conf in parents.items():
                db.execute("INSERT OR IGNORE INTO edges(child_id, parent_id, confidence) VALUES (?,?,?)",
                           (entry.id, pid, conf))
        entry.parents = list(parents.keys())
        return entry.id

    def _compute_parents(self, db, entry: ContextEntry, rowid: int) -> dict[str, float]:
        parents: dict[str, float] = {}
        if entry.is_action:
            last_action = db.execute(
                "SELECT COALESCE(MAX(rowid), 0) FROM entries WHERE session_id = ? AND kind = 'action' AND rowid < ?",
                (entry.session_id, rowid),
            ).fetchone()[0]
            rows = db.execute(
                "SELECT id FROM entries WHERE session_id = ? AND kind IN ('source','secret') "
                "AND rowid > ? AND rowid < ? ORDER BY rowid",
                (entry.session_id, last_action, rowid),
            ).fetchall()
            for r in rows[-RECENCY_WINDOW:]:
                parents[r["id"]] = 0.4
        else:
            # file lineage: last writer of this path (any session -> cross-agent)
            prod = db.execute(
                "SELECT id FROM entries WHERE op = 'WriteFile' AND target_norm = ? AND id <> ? "
                "ORDER BY rowid DESC LIMIT 1",
                (_norm(entry.target), entry.id),
            ).fetchone()
            if prod:
                parents[prod["id"]] = 0.8
        return parents

    def get_entries(self, session_id: str) -> list[ContextEntry]:
        rows = self._db.execute(
            "SELECT * FROM entries WHERE session_id = ? ORDER BY rowid", (session_id,)
        ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def aggregate(self, session_id: str, action_entry: ContextEntry) -> Aggregate:
        """Graph trace_back over persisted edges (same semantics as GraphStore)."""
        agg = Aggregate()
        supporting: list[str] = []
        weakest = 1.0
        seen: set[str] = set()
        stack: list[tuple[str, float]] = list(self._parents(action_entry.id))
        while stack:
            nid, path_conf = stack.pop()
            if nid in seen:
                continue
            seen.add(nid)
            row = self._db.execute(
                "SELECT trust, sensitivity, bait FROM entries WHERE id = ?", (nid,)
            ).fetchone()
            if row is None:
                continue
            hit = False
            if row["trust"] == "untrusted":
                agg.reached_untrusted = True
                hit = True
            if row["sensitivity"] == "secret":
                agg.reached_secret = True
                hit = True
            if row["bait"]:
                agg.reached_bait = True
                hit = True
            if hit:
                supporting.append(nid)
                weakest = min(weakest, path_conf)
            for pid, conf in self._parents(nid):
                stack.append((pid, min(path_conf, conf)))
        agg.supporting_entry_ids = supporting
        agg.confidence = weakest if supporting else 1.0
        return agg

    def _parents(self, child_id: str):
        return [(r["parent_id"], r["confidence"]) for r in self._db.execute(
            "SELECT parent_id, confidence FROM edges WHERE child_id = ?", (child_id,))]

    # ---- William-compatible helpers ----

    def evidence(self, session_id: str) -> tuple[str | None, str | None]:
        """(last untrusted id, last secret id) -- the session-level signal
        William's decide() consumes. Pairs with our richer aggregate()."""
        row = self._db.execute(
            "SELECT (SELECT id FROM entries WHERE session_id = ? AND trust = 'untrusted' ORDER BY rowid DESC LIMIT 1),"
            "       (SELECT id FROM entries WHERE session_id = ? AND sensitivity = 'secret' ORDER BY rowid DESC LIMIT 1)",
            (session_id, session_id),
        ).fetchone()
        return (row[0], row[1])

    def kill(self, session_id: str) -> None:
        with self._db:
            self._db.execute("INSERT OR IGNORE INTO sessions(id, status) VALUES (?, 'KILLED')", (session_id,))
            self._db.execute("UPDATE sessions SET status = 'KILLED' WHERE id = ?", (session_id,))

    def is_killed(self, session_id: str) -> bool:
        row = self._db.execute("SELECT status FROM sessions WHERE id = ?", (session_id,)).fetchone()
        return bool(row) and row["status"] == "KILLED"

    def close(self) -> None:
        self._db.close()

    # ---- internal ----

    def _row_to_entry(self, r: sqlite3.Row) -> ContextEntry:
        labels = Labels(
            trust=Trust(r["trust"]), sensitivity=Sensitivity(r["sensitivity"]),
            bait=bool(r["bait"]), in_workspace=bool(r["in_workspace"]), confidence=r["confidence"],
        )
        ap = None
        if r["kind"] == "action":
            ap = ActionProps(is_exit=bool(r["is_exit"]), is_destructive=bool(r["is_destructive"]))
        entry = ContextEntry(
            id=r["id"], ts=r["ts"], session_id=r["session_id"], kind=Kind(r["kind"]),
            channel=Channel(r["channel"]), op=Op(r["op"]), target=r["target"], origin=r["origin"],
            labels=labels, action_props=ap, verdict=r["verdict"], rule=r["rule"],
        )
        entry.parents = [pid for pid, _ in self._parents(r["id"])]
        return entry
