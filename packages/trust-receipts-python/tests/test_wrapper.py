"""
Tests for sonate.wrapper.TrustReceipts (high-level API).

Covers wrap()/create_receipt(), response extraction, chaining, and chain
verification.
"""

import pytest

from sonate import TrustReceipts, get_public_key

SEED = "42" * 32
PUB = get_public_key(SEED)


def make_sdk() -> TrustReceipts:
    return TrustReceipts(
        private_key=SEED,
        default_agent_did="did:sonate:agent-1",
        default_human_did="did:sonate:human-1",
    )


def test_init_derives_public_key():
    sdk = make_sdk()
    assert sdk.get_public_key() == PUB


def test_generate_key_pair_static():
    priv, pub = TrustReceipts.generate_key_pair()
    assert get_public_key(priv) == pub


def test_create_receipt_signs_and_verifies():
    sdk = make_sdk()
    receipt = sdk.create_receipt(
        session_id="s1", prompt="hi", response="hello", model="gpt-4",
        timestamp="2026-01-01T00:00:00.000Z",
    )
    assert sdk.verify_receipt(receipt) is True
    assert receipt["chain"]["previous_hash"] == "GENESIS"
    assert receipt["chain"]["chain_length"] == 1


def test_wrap_executes_fn_and_extracts_openai():
    sdk = make_sdk()
    resp, receipt = sdk.wrap(
        lambda: {"choices": [{"message": {"content": "Paris"}}]},
        session_id="s1", input="capital of France?", model="gpt-4",
        timestamp="2026-01-01T00:00:00.000Z",
    )
    assert resp["choices"][0]["message"]["content"] == "Paris"
    assert sdk.verify_receipt(receipt)


def test_wrap_extracts_anthropic():
    sdk = make_sdk()
    _, receipt = sdk.wrap(
        lambda: {"content": [{"text": "Hello there"}]},
        session_id="s1", input="hi", model="claude-3",
        timestamp="2026-01-01T00:00:00.000Z",
    )
    assert sdk.verify_receipt(receipt)


def test_three_receipt_chain_links_and_verifies():
    sdk = make_sdk()
    r1 = sdk.create_receipt(session_id="s", prompt="a", response="1", model="m",
                            timestamp="2026-01-01T00:00:00.000Z")
    r2 = sdk.create_receipt(session_id="s", prompt="b", response="2", model="m",
                            previous_receipt=r1, timestamp="2026-01-01T00:00:01.000Z")
    r3 = sdk.create_receipt(session_id="s", prompt="c", response="3", model="m",
                            previous_receipt=r2, timestamp="2026-01-01T00:00:02.000Z")

    assert r2["chain"]["previous_hash"] == r1["chain"]["chain_hash"]
    assert r3["chain"]["previous_hash"] == r2["chain"]["chain_hash"]
    assert [r["chain"]["chain_length"] for r in (r1, r2, r3)] == [1, 2, 3]

    result = sdk.verify_chain([r1, r2, r3])
    assert result["valid"] is True
    assert result["errors"] == []


def test_verify_chain_detects_broken_link():
    sdk = make_sdk()
    r1 = sdk.create_receipt(session_id="s", prompt="a", response="1", model="m",
                            timestamp="2026-01-01T00:00:00.000Z")
    r2 = sdk.create_receipt(session_id="s", prompt="b", response="2", model="m",
                            previous_receipt=r1, timestamp="2026-01-01T00:00:01.000Z")
    # r3 not chained to r2
    r3 = sdk.create_receipt(session_id="s", prompt="c", response="3", model="m",
                            timestamp="2026-01-01T00:00:02.000Z")
    result = sdk.verify_chain([r1, r2, r3])
    assert result["valid"] is False
    assert any("chain broken" in e for e in result["errors"])


def test_generated_key_wrap_roundtrip():
    sdk = TrustReceipts(default_agent_did="did:sonate:a", default_human_did="did:sonate:h")
    _, receipt = sdk.wrap(lambda: "response", session_id="s", input="prompt", model="m")
    assert sdk.verify_receipt(receipt)
