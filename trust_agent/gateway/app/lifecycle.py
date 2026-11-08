"""Transactional lifecycle metadata; shares the provenance SQLite transaction."""
import copy
import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import asdict

from provenance import ActionProps, Channel, ContextEntry, Kind, Labels, Op, Sensitivity, Trust


def encode_entry(entry):
    return asdict(entry)


def decode_entry(value):
    raw = dict(value)
    labels = dict(raw['labels'])
    labels.update(trust=Trust(labels['trust']), sensitivity=Sensitivity(labels['sensitivity']))
    raw.update(labels=Labels(**labels), op=Op(raw['op']), kind=Kind(raw['kind']), channel=Channel(raw['channel']))
    if raw.get('action_props') is not None:
        raw['action_props'] = ActionProps(**raw['action_props'])
    return ContextEntry(**raw)


class Lifecycle:
    def __init__(self, store):
        self.store = store
        self.db = getattr(store, '_db', None)
        self.shared = self.db is not None
        if not self.shared:
            self.db = sqlite3.connect(':memory:', check_same_thread=False)
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS lifecycle_state (
              kind TEXT, key TEXT, value TEXT NOT NULL, PRIMARY KEY(kind,key));
            CREATE TABLE IF NOT EXISTS lifecycle_audit (
              seq INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
              payload TEXT NOT NULL);
        ''')
        self.db.commit()

    @contextmanager
    def transaction(self):
        snapshot = None if self.shared else copy.deepcopy(self.store.__dict__)
        manager = self.store.transaction() if self.shared else self.db
        try:
            with manager:
                yield
        except BaseException:
            if snapshot is not None:
                self.store.__dict__.clear()
                self.store.__dict__.update(snapshot)
            raise

    def get(self, kind, key, default=None):
        row = self.db.execute('SELECT value FROM lifecycle_state WHERE kind=? AND key=?',
                              (kind, json.dumps(key))).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, kind, key, value):
        self.db.execute('INSERT INTO lifecycle_state VALUES (?,?,?) ON CONFLICT(kind,key) DO UPDATE SET value=excluded.value',
                        (kind, json.dumps(key), json.dumps(value)))

    def values(self, kind):
        return [json.loads(r[0]) for r in self.db.execute('SELECT value FROM lifecycle_state WHERE kind=?', (kind,))]

    def log(self, session, event):
        event = dict(event, session_id=session, ts=time.time())
        cursor = self.db.execute('INSERT INTO lifecycle_audit(session_id,payload) VALUES (?,?)', (session, json.dumps(event)))
        return cursor.lastrowid

    def events(self, session=None, after=0):
        rows = self.db.execute('SELECT seq,payload FROM lifecycle_audit WHERE seq>? AND (? IS NULL OR session_id=?) ORDER BY seq LIMIT 1000',
                               (after, session, session))
        return [dict(json.loads(r[1]), seq=r[0]) for r in rows]
