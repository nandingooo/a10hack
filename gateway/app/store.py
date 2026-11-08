import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from time import time

from .policy import Evidence


class Store:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    sensor_token_hash TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'KILLED'))
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY,
                    session_id TEXT NOT NULL REFERENCES sessions(id),
                    kind TEXT NOT NULL CHECK (kind IN ('decision', 'result', 'stop')),
                    decision_id INTEGER REFERENCES events(id),
                    timestamp REAL NOT NULL,
                    details TEXT NOT NULL,
                    trust TEXT,
                    sensitivity TEXT,
                    UNIQUE (session_id, decision_id)
                );
                CREATE INDEX IF NOT EXISTS session_events ON events(session_id, id);
                CREATE INDEX IF NOT EXISTS session_untrusted ON events(session_id, id) WHERE trust = 'untrusted';
                CREATE INDEX IF NOT EXISTS session_secret ON events(session_id, id) WHERE sensitivity = 'secret';
            """)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=2)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        return db

    @contextmanager
    def write(self):
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            yield db

    @staticmethod
    def append(db, session_id, kind, details, *, decision_id=None, trust=None, sensitivity=None) -> int:
        cursor = db.execute(
            """INSERT INTO events(session_id, kind, decision_id, timestamp, details, trust, sensitivity)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (session_id, kind, decision_id, time(), json.dumps(details), trust, sensitivity),
        )
        return cursor.lastrowid

    @staticmethod
    def evidence(db, session_id) -> Evidence:
        row = db.execute(
            """SELECT
                (SELECT id FROM events WHERE session_id = ? AND trust = 'untrusted' ORDER BY id DESC LIMIT 1),
                (SELECT id FROM events WHERE session_id = ? AND sensitivity = 'secret' ORDER BY id DESC LIMIT 1)""",
            (session_id, session_id),
        ).fetchone()
        return Evidence(untrusted=row[0], secret=row[1])
