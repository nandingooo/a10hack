"""The opt-in source-level trace gate (engine.trace_gate).

Default (off): the conservative session union decides — sound but over-blocks.
On: the decision is made from the graph trace_back (the actual sequence of
sources that flow INTO the action), which removes the design-sanctioned
`untrusted_destructive` over-block while keeping the union as the floor where the
action is genuinely connected to the poison.

VENDOR path matches the policy origin rule (**/vendor/**) -> cloned-repo -> untrusted,
so no explicit origin is needed.
"""
from service import Brain

VENDOR = "/repo/vendor/parser/lexer.py"


def d(brain, op, target, **args):
    return brain.decide({"session_id": "s", "op": op, "target": target, "args": args})


def _unrelated_destructive(brain):
    """untrusted read, then an intervening WriteFile (consumes the working set),
    then a clean read feeding a destructive command that does NOT touch the
    vendored file."""
    d(brain, "ReadFile", VENDOR)                 # untrusted somewhere in the session
    d(brain, "WriteFile", "/repo/out.txt")       # intervening sink resets the recency working set
    d(brain, "ReadFile", "/repo/src/app.py")     # clean read now feeds the next action
    return d(brain, "RunCommand", "rm -rf src/app.py", command="rm -rf src/app.py")


def test_union_floor_blocks_unrelated_destructive_when_gate_off():
    # Sound-but-coarse fallback (trace_gate explicitly off): any untrusted anywhere
    # in the session blocks the destructive op.
    v = _unrelated_destructive(Brain(trace_gate=False))
    assert v["decision"] == "block" and v["rule"] == "untrusted_destructive"


def test_trace_gate_allows_unrelated_destructive_by_default():
    # Default (gate ON): the rm's inputs don't trace back to the vendored file -> allowed.
    v = _unrelated_destructive(Brain())
    assert v["decision"] == "allow"
    assert v["trace_gate"] is True


def test_trace_gate_still_blocks_connected_destructive():
    # Soundness kept where it matters: the untrusted read still feeds this action.
    b = Brain(trace_gate=True)
    d(b, "ReadFile", VENDOR)                      # still in the working set (no intervening sink)
    v = d(b, "RunCommand", "rm -rf tmpdir", command="rm -rf tmpdir")
    assert v["decision"] == "block" and v["rule"] == "untrusted_destructive"
    assert VENDOR in v.get("trace_path", [])


def test_verdict_carries_traced_sequence():
    # Every consequential verdict returns the sequence of sources it traced.
    b = Brain(trace_gate=True)
    d(b, "ReadFile", VENDOR)
    v = d(b, "NetworkRequest", "evil.example")
    assert v["decision"] == "block" and v["rule"] == "lethal_trifecta"
    assert v["trace_path"] == [VENDOR]
    assert 0.0 < v["trace_confidence"] <= 1.0


def test_strict_session_keeps_union_floor_even_with_trace_gate():
    # In a strict/opaque sandbox we can't observe the real data flow, so the
    # union floor still blocks regardless of the trace.
    b = Brain(trace_gate=True)
    b.configure_session("strict-s", strict=True, workspace_root="/work")
    req = lambda op, target, **a: b.decide(
        {"session_id": "strict-s", "op": op, "target": target, "phase": "before",
         "tool_use_id": target + op, "cwd": "/work", "args": a})
    req("ReadFile", "/work/vendor/x.py")          # untrusted read (strict)
    v = req("RunCommand", "rm -rf /work/keep", command="rm -rf /work/keep")
    assert v["decision"] == "block"
