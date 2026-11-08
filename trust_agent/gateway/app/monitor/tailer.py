"""Incremental JSONL tailer (stdlib only).

Tracks a byte offset per file and returns only newly-appended COMPLETE lines on
each call. A partial last line (no trailing newline yet) is withheld until it
completes. Handles truncation/rotation by resetting when the file shrinks.
"""
from __future__ import annotations

import os


class JsonlTailer:
    def __init__(self, path: str) -> None:
        self.path = path
        self._offset = 0

    def read_new(self) -> list[str]:
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return []
        if size < self._offset:      # file was truncated/rotated
            self._offset = 0
        if size == self._offset:
            return []
        with open(self.path, "rb") as f:
            f.seek(self._offset)
            data = f.read()
        nl = data.rfind(b"\n")
        if nl == -1:                 # no complete line yet; hold the partial
            return []
        consumed = data[: nl + 1]
        self._offset += len(consumed)
        return [ln.decode("utf-8", "replace") for ln in consumed.splitlines() if ln.strip()]
