import posixpath
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class DecideRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(min_length=1, max_length=64)
    channel: Literal["hook", "egress", "mcp", "model"]
    op: Literal["ReadFile", "WriteFile", "DeleteFile", "NetworkRequest", "CallTool", "RunCommand", "ModelCall"]
    target: str = Field(min_length=1, max_length=1024, pattern=r"^[^\x00-\x1f\x7f]+$")
    origin: Literal["user", "operator", "workspace", "cloned-repo", "web", "tool-output", "download", "unknown"] = "unknown"
    inspected_body: SecretStr | None = Field(default=None, max_length=65536)


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(min_length=1, max_length=64)
    decision_id: int = Field(gt=0)
    outcome: Literal["succeeded", "failed", "unknown"]
    released_data: bool = Field(default=False, strict=True)


@dataclass(frozen=True)
class Evidence:
    untrusted: int | None
    secret: int | None


@dataclass(frozen=True)
class Verdict:
    decision: Literal["allow", "block", "stop"]
    rule: str
    reason: str
    evidence_ids: tuple[int, ...] = ()


FILE_OPS = {"ReadFile", "WriteFile", "DeleteFile"}
BAIT_FILES = {"aws_prod_credentials.txt", ".env.production.local"}
BAIT_TOKEN = "AKIA_FAKE_BAIT_DO_NOT_USE"
APPROVED_HOSTS = ("github.com", "pypi.org", "*.pythonhosted.org", "bedrock-runtime.*.amazonaws.com")
HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")
SESSION_KILLED = Verdict("stop", "session_killed", "This session has already been stopped.")


def file_labels(target: str, origin: str) -> tuple[str, str]:
    path = PurePosixPath(target)
    trust = "trusted" if origin in {"user", "operator"} else "untrusted"
    secret = (
        path.name in {".env", *BAIT_FILES}
        or fnmatchcase(path.name, "*token*")
        or fnmatchcase(path.name, "*.pem")
        or fnmatchcase(path.name, "id_rsa*")
        or ".ssh" in path.parts
        or path.parts[-2:] == (".aws", "credentials")
    )
    return trust, "secret" if secret else "public"


def decide(request: DecideRequest, evidence: Evidence, workspace: PurePosixPath) -> Verdict:
    target = request.target
    if (request.op in {"NetworkRequest", "CallTool"} and request.inspected_body is not None
            and BAIT_TOKEN in request.inspected_body.get_secret_value()):
        return Verdict("stop", "bait_touched", "The inspected outbound body contains the planted canary.")

    if request.op in FILE_OPS:
        if not target.startswith("/") or target.startswith("//") or posixpath.normpath(target) != target:
            return Verdict("block", "invalid_target", "The sensor must supply a normalized absolute path.")
        path = PurePosixPath(target)
        if path.name in BAIT_FILES:
            return Verdict("stop", "bait_touched", "The request targets a planted canary file.")
        if not path.is_relative_to(workspace):
            return Verdict("block", "outside_workspace", "The target is outside the managed workspace.")
        if request.op != "ReadFile" and (path == workspace or path.is_relative_to(workspace / ".git")):
            return Verdict("block", "protected_path", "The target is protected by workspace policy.")
        if request.op == "DeleteFile" and evidence.untrusted is not None:
            return Verdict("block", "untrusted_destructive", "This run received untrusted input before attempting a deletion.", (evidence.untrusted,))
    elif request.op == "NetworkRequest":
        host = target.lower().removesuffix(".")
        if len(host) > 253 or not HOSTNAME.fullmatch(host) or not any(fnmatchcase(host, pattern) for pattern in APPROVED_HOSTS):
            return Verdict("block", "egress_allowlist", "The destination is outside the outbound host allowlist.")
    elif request.op == "CallTool" and request.channel == "mcp" and target == "post_support_update":
        if evidence.secret is not None:
            ids = tuple(sorted({value for value in (evidence.secret, evidence.untrusted) if value is not None}))
            return Verdict("block", "secret_external_write", "This run received secret data before attempting an external write.", ids)
    else:
        return Verdict("block", "unsupported_action", "The guard has no registered policy for this action.")

    return Verdict("allow", "policy_allows", "The configured policy permits this request.")
