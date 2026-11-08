"""Score files with the real classifier model (ProtectAI), to pick PROMPT_GUARD_THRESHOLD from data.

  pip install -r gateway/requirements-guard.txt
  python gateway/score_files.py                     # every file in gateway/workspace/files
  python gateway/score_files.py some.md other.html  # or specific files

Prints the read's score (what the gateway would use), the score of the visible text (first
PROMPT_GUARD_MAX_CHARS), the best hidden-part score and the time taken. Files are only read and scored; nothing in them is acted on.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import classifier  # noqa: E402


def main(paths: list[str]) -> None:
    files = [Path(p) for p in paths] or sorted(p for p in (HERE / "workspace/files").rglob("*") if p.is_file())
    t0 = time.perf_counter()
    classifier.model_score("warm up")
    print(f"model {classifier.MODEL} loaded in {time.perf_counter() - t0:.1f}s; "
          f"threshold {classifier.THRESHOLD}\n")
    print(f"{'score':>6} {'full':>6} {'hidden':>6} {'ms':>6}  {'':4} file")
    for f in files:
        text = f.read_bytes()[:256 * 1024].decode(errors="replace")
        parts, _ = classifier.segments(text)
        t = time.perf_counter()
        scores = [classifier.model_score(p) for p in parts]
        ms = (time.perf_counter() - t) * 1000
        hidden = max(scores[1:], default=None)
        flag = "FLAG" if max(scores) >= classifier.THRESHOLD else ""
        print(f"{max(scores):6.3f} {scores[0]:6.3f} {'' if hidden is None else f'{hidden:.3f}':>6} "
              f"{ms:6.0f}  {flag:4} {f}")


if __name__ == "__main__":
    main(sys.argv[1:])
