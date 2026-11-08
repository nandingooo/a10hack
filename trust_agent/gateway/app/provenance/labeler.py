"""Deterministic labeler + shared helpers (AGENTS.md section 7). No AI (Invariant 6).

Maps an activity's (path/target, origin) to ``Labels`` using policy globs from
``labels.yaml``. Also provides the helpers the guard/sensors share:
``match``, ``in_ws``, ``approved_host``, ``is_bait_target``, ``classify_origin``.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Optional

from .tags import Labels, Sensitivity, Trust

_DEFAULT_CFG = os.path.join(os.path.dirname(__file__), "..", "..", "policy", "labels.yaml")


def _glob_to_regex(glob: str) -> "re.Pattern[str]":
    """Translate a glob to a regex. ``**`` matches any depth (incl ``/``);
    ``*`` matches within a path segment; ``?`` matches one non-``/`` char."""
    out: list[str] = []
    i = 0
    while i < len(glob):
        if glob[i:i + 2] == "**":
            out.append(".*")
            i += 2
            continue
        c = glob[i]
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def match(path: str, globs: list[str]) -> bool:
    p = str(path).replace("\\", "/")
    return any(_glob_to_regex(g).match(p) for g in globs)


@dataclass
class Policy:
    trusted_origins: list[str]
    untrusted_origins: list[str]
    secret_globs: list[str]
    sensitive_globs: list[str]
    bait_files: list[str]
    bait_token: str
    approved_hosts: list[str]
    workspace_root: str
    default_origin: str = "cloned-repo"
    origin_rules: list[dict] = field(default_factory=list)
    receivers: list[dict] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)

    @staticmethod
    def load(path: str = _DEFAULT_CFG) -> "Policy":
        import yaml  # lazy import so tests can build Policy() without PyYAML
        with open(path, "r", encoding="utf-8") as f:
            d = yaml.safe_load(f)
        return Policy(
            trusted_origins=d["trust"]["trusted"],
            untrusted_origins=d["trust"]["untrusted"],
            secret_globs=d["sensitivity"]["secret"],
            sensitive_globs=d["sensitivity"].get("sensitive", []),
            bait_files=d["bait"]["files"],
            bait_token=d["bait"]["token"],
            approved_hosts=d["egress"]["approved_hosts"],
            workspace_root=d["workspace_root"],
            default_origin=d.get("sources", {}).get("default_origin", "cloned-repo"),
            origin_rules=d.get("sources", {}).get("rules", []),
            receivers=d.get("egress", {}).get("receivers", []),
            allowed_tools=d.get("tools", {}).get("allowed", []),
        )

    def origin(self, path: str) -> str:
        for rule in self.origin_rules:
            if match(path, rule["paths"]):
                return rule["origin"]
        return self.default_origin


class Labeler:
    def __init__(self, policy: Optional[Policy] = None) -> None:
        self.cfg = policy or Policy.load()

    def classify_origin(self, origin: str) -> Trust:
        if origin in self.cfg.trusted_origins:
            return Trust.TRUSTED
        if origin in self.cfg.untrusted_origins:
            return Trust.UNTRUSTED
        return Trust.UNTRUSTED  # Invariant 2: unknown -> untrusted (fail closed)

    def in_ws(self, path: str) -> bool:
        p = str(path).replace("\\", "/")
        root = self.cfg.workspace_root.replace("\\", "/").rstrip("/")
        if not root:
            return False
        try:
            return PurePosixPath(p).is_relative_to(root)
        except Exception:
            return p == root or p.startswith(root + "/")

    def approved_host(self, host: str) -> bool:
        return match(host or "", self.cfg.approved_hosts)

    def is_bait_target(self, op: str, target: str, body: str = "") -> bool:
        if match(target or "", self.cfg.bait_files):
            return True
        blob = f"{target or ''} {body or ''}"
        # the canary token leaving via ANY channel (curl in a bash cmd, a web body) is a confirmed leak
        if self.cfg.bait_token and self.cfg.bait_token in blob:
            return True
        # a bait filename referenced inside a command/body (e.g. `cat aws_prod_credentials.txt`)
        for pattern in self.cfg.bait_files:
            base = pattern.replace("\\", "/").rsplit("/", 1)[-1]
            if base and base in blob:
                return True
        return False

    def label(self, path: str, origin: str) -> Labels:
        trust = self.classify_origin(origin)
        if match(path, self.cfg.secret_globs):
            sens = Sensitivity.SECRET
        elif match(path, self.cfg.sensitive_globs):
            sens = Sensitivity.SENSITIVE
        else:
            sens = Sensitivity.PUBLIC
        return Labels(
            trust=trust,
            sensitivity=sens,
            bait=match(path, self.cfg.bait_files),
            in_workspace=self.in_ws(path),
            confidence=1.0,
        )
