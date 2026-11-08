"""Prompt-injection classifier on the gateway's read path (ProtectAI DeBERTa v3, by default).

Off unless PROMPT_GUARD=1. It can only make a session stricter: a flagged read is absorbed
as untrusted, so R1/R3 do the blocking. A miss leaves the rules exactly where they were.

  PROMPT_GUARD=1                      turn it on
  PROMPT_GUARD_MODEL=...              default protectai/deberta-v3-base-prompt-injection-v2
                                      (Apache 2.0, not gated); also works with
                                      meta-llama/Llama-Prompt-Guard-2-86M or -22M (gated)
  PROMPT_GUARD_THRESHOLD=0.5          injection-probability cutoff
  PROMPT_GUARD_MAX_CHARS=16384        how much of the text is scored (hidden parts always in full)
  PROMPT_GUARD_WINDOW=512             tokens per scoring window
  HF_TOKEN=...                        only for the gated Llama models' first download

What gets scored: the first 16 KiB of the text (zero-width characters removed), plus every
hidden part (HTML comments, <script>/<style>, display:none blocks) in full and on its own, so
an injection tucked into a comment isn't diluted by the visible page and can't be pushed past
the limit. Text is split into overlapping 512-token windows; the read's score is the highest
window score. The limit keeps the 86M model to ~2 s per read on CPU in the worst case; visible
text past it is not scored (tags and rules still apply to it).

Measured with eval_guard.py: ProtectAI catches the most injections of the models tried
(12/20 of our cases, 22/60 deepset, 197/300 InjecAgent plain-wording attacks) but also
flags many harmless texts, most of all JSON tool output (223/334 InjecAgent harmless
outputs), which then counts as untrusted. Prompt Guard 86M flags almost nothing harmless
but only catches override wording ("ignore previous instructions"). Tags and rules remain
the main defence.
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
MODEL = os.environ.get("PROMPT_GUARD_MODEL", "protectai/deberta-v3-base-prompt-injection-v2")
THRESHOLD = float(os.environ.get("PROMPT_GUARD_THRESHOLD", "0.5"))
MAX_CHARS = int(os.environ.get("PROMPT_GUARD_MAX_CHARS", str(16 * 1024)))
WINDOW = int(os.environ.get("PROMPT_GUARD_WINDOW", "512"))
STRIDE, BATCH = min(64, WINDOW // 4), 16

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
    truncated: bool = False


def segments(text: str) -> tuple[list[str], int]:
    """The first MAX_CHARS of the normalized text, then every hidden part in full."""
    text = _ZERO_WIDTH.sub("", text)
    hidden = [m.groups()[-1].strip() for rx in _HIDDEN for m in rx.finditer(text)]
    hidden = [h for h in hidden if h]
    return [text[:MAX_CHARS], *hidden], len(hidden)


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
    v = Verdict(round(score, 4), score >= THRESHOLD, hidden, len(text) > MAX_CHARS)
    _cache[key] = v
    if len(_cache) > _CACHE_MAX:
        _cache.popitem(last=False)
    return v


def warm() -> None:
    """Load the model at startup so the first read doesn't pay for it (and a bad token fails loudly)."""
    if ENABLED and scorer is model_score:
        model_score("warm up")
