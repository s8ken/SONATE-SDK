"""
Tests for sonate.trust_receipt.TrustReceipt (v2.2.0).

Covers construction, the contract-ordered signing pipeline, verification, id
integrity on load, tamper detection on every field, and legacy-arg mapping.
"""

import copy

import pytest

from sonate import TrustReceipt, get_public_key, sha256_hex, verify_receipt

SEED = "42" * 32
PUB = get_public_key(SEED)


def make(**overrides) -> TrustReceipt:
    kwargs = dict(
        session_id="s-1",
        agent_did="did:sonate:agent-1",
        human_did="did:sonate:human-1",
        mode="constitutional",
        prompt="What is 2+2?",
        response="4",
        model="gpt-4",
        provider="openai",
        policy_version="2.0.0",
        telemetry={"resonance_score": 0.9, "overall_trust_score": 88},
        # Current time: verify() applies the default one-year maximum age.
        timestamp=None,
    )
    kwargs.update(overrides)
    return TrustReceipt(**kwargs)


def test_sign_produces_v220_structure():
    data = make().sign(SEED).to_json()
    assert data["version"] == "2.2.0"
    assert set(["id", "timestamp", "session_id", "agent_did", "human_did", "mode",
                "interaction", "chain", "signature"]).issubset(data.keys())
    assert data["signature"]["algorithm"] == "Ed25519"
    assert data["chain"]["previous_hash"] == "GENESIS"


def test_interaction_is_privacy_by_default():
    inter = make().sign(SEED).to_json()["interaction"]
    assert "prompt" not in inter and "response" not in inter
    assert inter["prompt_hash"] == sha256_hex("What is 2+2?")
    assert inter["response_hash"] == sha256_hex("4")


def test_include_content_keeps_raw():
    inter = make(include_content=True).sign(SEED).to_json()["interaction"]
    assert inter["prompt"] == "What is 2+2?"
    assert inter["response"] == "4"
    assert inter["prompt_hash"] == sha256_hex("What is 2+2?")


def test_roundtrip_verifies():
    data = make().sign(SEED).to_json()
    assert verify_receipt(data, PUB).valid is True
    assert make().sign(SEED).verify(PUB) is True


def test_id_is_hash_of_canonical_payload():
    from sonate import contract
    data = make().sign(SEED).to_json()
    assert data["id"] == contract.generate_receipt_id(data)


def test_from_json_rejects_tampered_id():
    data = make().sign(SEED).to_json()
    data["id"] = "0" * 64
    with pytest.raises(ValueError, match="id does not match"):
        TrustReceipt.from_json(data)


def test_from_json_roundtrip_preserves_bytes():
    data = make().sign(SEED).to_json()
    restored = TrustReceipt.from_json(data)
    assert restored.to_json() == data
    assert restored.verify(PUB) is True


@pytest.mark.parametrize("mutate", [
    lambda d: d["interaction"].__setitem__("prompt_hash", "0" * 64),
    lambda d: d["interaction"].__setitem__("response_hash", "0" * 64),
    lambda d: d["interaction"].__setitem__("model", "evil-model"),
    lambda d: d.__setitem__("session_id", "hacked"),
    lambda d: d.__setitem__("agent_did", "did:sonate:evil"),
    lambda d: d.__setitem__("timestamp", "2025-06-01T00:00:00.000Z"),
    lambda d: d.__setitem__("mode", "directive"),
    lambda d: d["telemetry"].__setitem__("overall_trust_score", 100),
    lambda d: d["signature"].__setitem__("value", "0" * 128),
    lambda d: d["chain"].__setitem__("chain_hash", "0" * 64),
])
def test_tamper_any_field_fails_verification(mutate):
    data = make().sign(SEED).to_json()
    mutate(data)
    assert verify_receipt(data, PUB).valid is False


def test_wrong_public_key_fails():
    data = make().sign(SEED).to_json()
    other = get_public_key("11" * 32)
    result = verify_receipt(data, other)
    assert result.valid is False
    assert result.checks["signature"].passed is False


def test_agent_id_mapped_to_did():
    r = make(agent_did=None, agent_id="agent-xyz", human_did=None, human_id="human-xyz")
    assert r.agent_did == "did:sonate:agent-xyz"
    assert r.human_did == "did:sonate:human-xyz"


def test_scores_alias_splits_ciq_and_custom():
    # Matches the JS SDK mapping exactly (== full-content fixture's telemetry).
    r = make(telemetry=None, scores={"clarity": 0.9, "integrity": 0.9, "quality": 0.9, "safety": 0.97})
    assert r.telemetry == {
        "ciq_metrics": {"clarity": 0.9, "integrity": 0.9, "quality": 0.9},
        "custom_scores": {"safety": 0.97},
    }


def test_scores_alias_only_ciq_has_no_custom_scores():
    r = make(telemetry=None, scores={"clarity": 0.8, "integrity": 0.7, "quality": 0.6})
    assert r.telemetry == {"ciq_metrics": {"clarity": 0.8, "integrity": 0.7, "quality": 0.6}}
    assert "custom_scores" not in r.telemetry


def test_scores_alias_only_custom_has_no_ciq_metrics():
    r = make(telemetry=None, scores={"resonance_score": 0.77})
    assert r.telemetry == {"custom_scores": {"resonance_score": 0.77}}
    assert "ciq_metrics" not in r.telemetry


def test_scores_merge_over_explicit_telemetry():
    r = make(
        telemetry={"ciq_metrics": {"clarity": 0.1}, "overall_trust_score": 50},
        scores={"clarity": 0.99, "safety": 0.5},
    )
    # scores win on collision within their bucket; other telemetry preserved.
    assert r.telemetry == {
        "ciq_metrics": {"clarity": 0.99},
        "overall_trust_score": 50,
        "custom_scores": {"safety": 0.5},
    }


def test_no_scores_and_no_telemetry_omits_telemetry():
    data = make(telemetry=None, scores=None).sign(SEED).to_json()
    assert "telemetry" not in data


def test_prev_receipt_hash_maps_to_previous_hash():
    r = make(prev_receipt_hash="a" * 64, chain_length=2).sign(SEED).to_json()
    assert r["chain"]["previous_hash"] == "a" * 64
    assert r["chain"]["chain_length"] == 2


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        make(mode="freeform")


def test_optional_fields_omitted_when_absent():
    data = make(policy_version=None, telemetry=None, metadata=None).sign(SEED).to_json()
    assert "policy_version" not in data
    assert "telemetry" not in data
    assert "metadata" not in data
    assert verify_receipt(data, PUB).valid is True


# ── Regression tests from review ──────────────────────────────────────────

def test_from_json_preserves_empty_telemetry():
    receipt = make(telemetry=None)
    receipt.telemetry = {}  # allowed by the schema; a producer may emit it
    data = receipt.sign(SEED).to_json()
    assert data["telemetry"] == {}
    assert verify_receipt(data, PUB).valid is True
    restored = TrustReceipt.from_json(data)
    assert restored.verify(PUB) is True
    assert restored.to_json() == data


def test_to_json_returns_an_independent_copy():
    receipt = make(metadata={"tags": ["a"]}).sign(SEED)
    data = receipt.to_json()
    data["metadata"]["tags"].append("b")
    data["interaction"]["model"] = "other"
    data["telemetry"]["overall_trust_score"] = 1
    assert receipt.verify(PUB) is True
    assert receipt.to_json()["metadata"] == {"tags": ["a"]}


def test_from_json_is_independent_of_the_source_dict():
    data = make(metadata={"turn": 1}).sign(SEED).to_json()
    restored = TrustReceipt.from_json(data)
    data["metadata"]["turn"] = 2
    data["interaction"]["model"] = "other"
    assert restored.verify(PUB) is True


def test_verify_receipt_returns_invalid_for_uncanonicalizable_numbers():
    data = make().sign(SEED).to_json()
    data["metadata"] = {"n": 2**63 - 1}  # no JavaScript producer could sign this
    result = verify_receipt(data, PUB)
    assert result.valid is False
    assert result.checks["hash"].passed is False
    assert result.checks["chain"].passed is False


def test_verify_receipt_rejects_numeric_signature_value():
    data = make().sign(SEED).to_json()
    data["signature"]["value"] = 2**40  # bytes(2**40) would try to allocate 1 TB
    result = verify_receipt(data, PUB)
    assert result.valid is False
    assert result.checks["signature"].passed is False
