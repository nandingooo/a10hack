"""Prompt-injection classifier on the gateway's read path (Llama Prompt Guard 2, 22M).

Off unless PROMPT_GUARD=1. It can only make a session stricter: a flagged read is absorbed
as untrusted, so R1/R3 do the blocking. A miss leaves the rules exactly where they were.

  PROMPT_GUARD=1                      turn it on
  PROMPT_GUARD_MODEL=...              default meta-llama/Llama-Prompt-Guard-2-22M (gated on HF)
  PROMPT_GUARD_THRESHOLD=0.5          malicious-probability cutoff
  HF_TOKEN=...                        needed to download the gated model the first time

What gets scored: the whole text (zero-width characters removed), plus each hidden part
(HTML comments, <script>/<style>, display:none blocks) on its own, so an injection tucked
into a comment isn't diluted by the visible page around it. The agent sees all of it, so
all of it is scored. Long text is split into overlapping 512-token windows; the read's score
is the highest window score.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger("gateway.classifier")

ENABLED = os.environ.get("PROMPT_GUARD", "0") == "1"
MODEL = os.environ.get("PROMPT_GUARD_MODEL", "meta-llama/Llama-Prompt-Guard-2-22M")
THRESHOLD = float(os.environ.get("PROMPT_GUARD_THRESHOLD", "0.5"))
WINDOW, STRIDE, BATCH = 512, 64, 16

_ZERO_WIDTH = re.compile("[​-\u200F⁠-⁤﻿­]")
_HIDDEN = [
    re.compile(r"<!--(.*?)-->", re.S),
    re.compile(r"<(script|style)\b[^>]*>(.*?)</\1>", re.S | re.I),
    re.compile(r"<(\w+)[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)"
               r"[^\"']*[\"'][^>]*>(.*?)</\1>", re.S | re.I),
]


@dataclass
class Verdict:
    score: float
    flagged: bool
    hidden_parts: int


def segments(text: str) -> tuple[list[str], int]:
    """The normalized full text, then each hidden part separately."""
    text = _ZERO_WIDTH.sub("", text)
    hidden = [m.groups()[-1].strip() for rx in _HIDDEN for m in rx.finditer(text)]
    hidden = [h for h in hidden if h]
    return [text, *hidden], len(hidden)


# ---------- model ----------

_lock = threading.Lock()
_model = None
_tok = None


def _load():
    global _model, _tok
    with _lock:
        if _model is None:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            _tok = AutoTokenizer.from_pretrained(MODEL)
            _model = AutoModelForSequenceClassification.from_pretrained(MODEL).eval()
            log.info("prompt guard loaded: %s (threshold %.2f)", MODEL, THRESHOLD)
    return _model, _tok


def model_score(text: str) -> float:
    """Highest malicious probability over 512-token windows of `text`."""
    import torch
    model, tok = _load()
    enc = tok(text, truncation=True, max_length=WINDOW, stride=STRIDE,
              return_overflowing_tokens=True, padding=True, return_tensors="pt")
    best = 0.0
    with torch.inference_mode():
        for i in range(0, enc["input_ids"].shape[0], BATCH):
            logits = model(input_ids=enc["input_ids"][i:i + BATCH],
                           attention_mask=enc["attention_mask"][i:i + BATCH]).logits
            best = max(best, torch.softmax(logits, dim=-1)[:, 1].max().item())
    return best


# Tests swap this for a fake so they don't need torch or the gated model.
scorer: Callable[[str], float] = model_score

_cache: OrderedDict[str, Verdict] = OrderedDict()
_CACHE_MAX = 512


def check(text: str) -> Verdict | None:
    """None when the classifier is off. Scoring errors are logged and treated as not flagged
    (the classifier only ever tightens, so failing open keeps today's behaviour)."""
    if not ENABLED or not text.strip():
        return None
    key = hashlib.sha256(text.encode(errors="replace")).hexdigest()
    if key in _cache:
        _cache.move_to_end(key)
        return _cache[key]
    parts, hidden = segments(text)
    try:
        score = max(scorer(p) for p in parts)
    except Exception as e:  # noqa: BLE001
        log.error("prompt guard failed, read not classified: %s", e)
        return None
    v = Verdict(round(score, 4), score >= THRESHOLD, hidden)
    _cache[key] = v
    if len(_cache) > _CACHE_MAX:
        _cache.popitem(last=False)
    return v


def warm() -> None:
    """Load the model at startup so the first read doesn't pay for it (and a bad token fails loudly)."""
    if ENABLED and scorer is model_score:
        model_score("warm up")
