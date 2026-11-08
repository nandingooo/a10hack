"""Tests for the multi-agent / inter-agent provenance primitives (stubs).

These cover taint-on-ingest (a message from a tainted agent is itself tainted),
cross-agent origin detection, and globally-unique entry ids used for cross-
session edges in the tree phase.
"""
from provenance import (
    Aggregate, Sensitivity, Trust,
    derive_inbound_labels, is_cross_agent_origin, new_entry_id, INBOUND_CONFIDENCE,
)


def test_message_from_clean_agent_is_trusted_public():
    sender = Aggregate()  # a clean sender
    lbl = derive_inbound_labels(sender)
    assert lbl.trust == Trust.TRUSTED
    assert lbl.sensitivity == Sensitivity.PUBLIC
    assert lbl.confidence == INBOUND_CONFIDENCE  # inferred edge, < 1.0


def test_message_from_untrusted_agent_is_untrusted():
    # A read something untrusted, then messages B -> B's inbound is untrusted.
    sender = Aggregate(reached_untrusted=True, supporting_entry_ids=["A:e3"])
    assert derive_inbound_labels(sender).effective_trust == Trust.UNTRUSTED


def test_secret_carrying_agent_marks_inbound_secret():
    sender = Aggregate(reached_secret=True)
    assert derive_inbound_labels(sender).sensitivity == Sensitivity.SECRET


def test_bait_propagates_across_the_edge():
    sender = Aggregate(reached_bait=True)
    assert derive_inbound_labels(sender).bait is True


def test_cross_agent_origin_detection():
    assert is_cross_agent_origin("agent:claude-7f3a")
    assert is_cross_agent_origin("shared:taskboard")
    assert not is_cross_agent_origin("cloned-repo")
    assert not is_cross_agent_origin("workspace")


def test_entry_ids_are_globally_unique_across_sessions():
    a = new_entry_id("sessA", 1)
    b = new_entry_id("sessB", 1)
    assert a != b
    assert a.startswith("sessA:") and b.startswith("sessB:")
