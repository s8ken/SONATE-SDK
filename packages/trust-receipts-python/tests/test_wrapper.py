"""
Tests for sonate.wrapper.TrustReceipts (high-level API).

Covers wrap()/create_receipt(), response extraction, chaining, and chain
verification.
"""

import pytest

from sonate import TrustReceipts, get_public_key, sha256_hex
from sonate.crypto import canonicalize

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
    )
    assert sdk.verify_receipt(receipt) is True
    assert receipt["chain"]["previous_hash"] == "GENESIS"
    assert receipt["chain"]["chain_length"] == 1


def test_wrap_executes_fn_and_extracts_openai():
    sdk = make_sdk()
    resp, receipt = sdk.wrap(
        lambda: {"choices": [{"message": {"content": "Paris"}}]},
        session_id="s1", input="capital of France?", model="gpt-4",
    )
    assert resp["choices"][0]["message"]["content"] == "Paris"
    assert sdk.verify_receipt(receipt)


def test_wrap_extracts_anthropic():
    sdk = make_sdk()
    _, receipt = sdk.wrap(
        lambda: {"content": [{"text": "Hello there"}]},
        session_id="s1", input="hi", model="claude-3",
    )
    assert sdk.verify_receipt(receipt)


def test_three_receipt_chain_links_and_verifies():
    sdk = make_sdk()
    r1 = sdk.create_receipt(session_id="s", prompt="a", response="1", model="m")
    r2 = sdk.create_receipt(session_id="s", prompt="b", response="2", model="m",
                            previous_receipt=r1)
    r3 = sdk.create_receipt(session_id="s", prompt="c", response="3", model="m",
                            previous_receipt=r2)

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


# ── Regression tests from review ──────────────────────────────────────────

class _Obj:
    """Attribute-only stand-in for the OpenAI and Anthropic SDK response models."""

    def __init__(self, **fields):
        self.__dict__.update(fields)


def test_wrap_extracts_openai_response_object():
    sdk = make_sdk()
    completion = _Obj(choices=[_Obj(message=_Obj(role="assistant", content="Paris"))])
    response, receipt = sdk.wrap(lambda: completion, session_id="s", input="q", model="gpt-4o")
    assert response is completion
    assert receipt["interaction"]["response_hash"] == sha256_hex("Paris")
    assert sdk.verify_receipt(receipt)


def test_wrap_extracts_anthropic_response_object():
    sdk = make_sdk()
    message = _Obj(content=[_Obj(type="text", text="Paris")])
    response, receipt = sdk.wrap(lambda: message, session_id="s", input="q", model="claude")
    assert response is message
    assert receipt["interaction"]["response_hash"] == sha256_hex("Paris")
    assert sdk.verify_receipt(receipt)


def test_wrap_hashes_unrecognized_pydantic_style_object_as_json():
    class Model:
        def model_dump(self, mode="python"):
            assert mode == "json"
            return {"content": [{"type": "tool_use", "name": "lookup"}]}

    sdk = make_sdk()
    response, receipt = sdk.wrap(lambda: Model(), session_id="s", input="q", model="claude")
    expected = sha256_hex(canonicalize({"content": [{"type": "tool_use", "name": "lookup"}]}))
    assert receipt["interaction"]["response_hash"] == expected
    assert sdk.verify_receipt(receipt)


def test_signed_receipt_unaffected_by_later_edits_to_caller_dicts():
    sdk = make_sdk()
    metadata = {"turn": 1, "tags": ["a"]}
    policy_state = {"rules": {"refund_limit": 50}}
    telemetry = {"ciq_metrics": {"clarity": 0.9}}
    r1 = sdk.create_receipt(session_id="s", prompt="p", response="r", model="m",
                            metadata=metadata, policy_state=policy_state, telemetry=telemetry)
    metadata["turn"] = 2
    metadata["tags"].append("b")
    policy_state["rules"]["refund_limit"] = 500
    telemetry["ciq_metrics"]["clarity"] = 0.1
    assert r1["metadata"] == {"turn": 1, "tags": ["a"]}
    assert sdk.verify_receipt(r1)


def test_chain_length_omitted_when_predecessor_position_unknown():
    sdk = make_sdk()
    previous = sdk.create_receipt(session_id="s", prompt="a", response="1", model="m")
    del previous["chain"]["chain_length"]  # optional field; the format allows it
    nxt = sdk.create_receipt(session_id="s", prompt="b", response="2", model="m",
                             previous_receipt=previous)
    assert nxt["chain"]["previous_hash"] == previous["chain"]["chain_hash"]
    assert "chain_length" not in nxt["chain"]
    assert sdk.verify_receipt(nxt)


def test_chain_length_increments_known_position():
    sdk = make_sdk()
    r1 = sdk.create_receipt(session_id="s", prompt="a", response="1", model="m")
    r2 = sdk.create_receipt(session_id="s", prompt="b", response="2", model="m", previous_receipt=r1)
    r3 = sdk.create_receipt(session_id="s", prompt="c", response="3", model="m", previous_receipt=r2)
    assert [r["chain"]["chain_length"] for r in (r1, r2, r3)] == [1, 2, 3]
