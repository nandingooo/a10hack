"""Web-fetched content is treated as an untrusted source (prompt-injection vector).

Verifies the by-design behavior that closes the "web content is not modeled as an
incoming untrusted source" gap: fetching web content -- even from an APPROVED host
-- marks the session's context untrusted, so a later outbound request to an
UNAPPROVED host is blocked as a lethal-trifecta flow (untrusted input reaching an
exit). A clean session hitting the same host is only an allowlist block, proving
the verdict is driven by provenance, not by the destination alone.
"""
import pytest
from service import Brain
from provenance.sqlite_store import SqliteStore


@pytest.fixture(params=['graph', 'sqlite'])
def brain(request):
    store = SqliteStore(':memory:') if request.param == 'sqlite' else None
    yield Brain(store)
    if store:
        store.close()


def before(b, tool, op, target, **args):
    return b.decide(dict(session_id='s', tool_use_id=tool, phase='before',
                         op=op, target=target, cwd='/repo', args=args))


def complete(b, tool, success=True):
    return b.complete(dict(session_id='s', tool_use_id=tool, success=success,
                           exposure='exposed' if success else 'none'))


def test_web_fetch_becomes_untrusted_source(brain):
    before(brain, 'fetch', 'NetworkRequest', 'github.com')
    complete(brain, 'fetch')
    entries = brain.store.get_entries('s')
    assert entries and entries[-1].labels.effective_trust.value == 'untrusted'


def test_web_content_then_exfil_to_unapproved_is_lethal_trifecta(brain):
    # 1. agent fetches web content from an approved host (could carry an injection)
    assert before(brain, 'fetch', 'NetworkRequest', 'github.com')['decision'] == 'allow'
    complete(brain, 'fetch')
    # 2. a later outbound request to an UNAPPROVED host is an untrusted->exit flow
    v = before(brain, 'exfil', 'NetworkRequest', 'attacker.example')
    assert v['decision'] == 'block'
    assert v['rule'] == 'lethal_trifecta'


def test_clean_session_exfil_is_only_allowlist(brain):
    # control: no untrusted context -> the same exit is a plain allowlist block,
    # not lethal_trifecta. Proves the rule is provenance-driven, not host-driven.
    v = before(brain, 'exfil', 'NetworkRequest', 'attacker.example')
    assert v['decision'] == 'block'
    assert v['rule'] == 'egress_allowlist'
