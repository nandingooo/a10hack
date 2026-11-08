"""Brain.agents(): live hook-mode sessions must be listed even though they are never configured."""
from service import Brain


def decide(brain, session, op, target, **args):
    return brain.decide({"session_id": session, "op": op, "target": target, "args": args})


def test_unconfigured_hook_sessions_are_listed_with_activity_counts():
    brain = Brain()
    decide(brain, "hook-a", "ReadFile", "/repo/vendor/README.md")
    decide(brain, "hook-a", "NetworkRequest", "evil.example")
    decide(brain, "hook-b", "ReadFile", "/repo/src/app.py")

    agents = {a["session_id"]: a for a in brain.agents()}

    assert set(agents) == {"hook-a", "hook-b"}
    assert agents["hook-a"]["decisions"] == 2
    assert agents["hook-a"]["denials"] == 1
    assert agents["hook-b"]["denials"] == 0
    assert all(a["status"] == "ACTIVE" and a["managed"] is False for a in agents.values())


def test_agents_sorted_newest_first_and_reflect_kill():
    brain = Brain()
    decide(brain, "old", "ReadFile", "/repo/a.py")
    decide(brain, "new", "ReadFile", "/repo/b.py")
    brain.kill("old")

    agents = brain.agents()

    assert agents[0]["session_id"] == "old"  # kill logs an event, making it the most recent
    assert {a["session_id"]: a["status"] for a in agents} == {"old": "KILLED", "new": "ACTIVE"}
