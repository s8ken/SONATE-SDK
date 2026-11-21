"""
Cross-language conformance tests.

Proves the Python SDK is byte-for-byte compatible with the JavaScript
implementation of the SONATE v2.2.0 receipt contract:

1. Independent construction — a receipt hand-built straight from the contract
   primitives verifies, and matches what the TrustReceipt class produces.
2. Python's own golden fixtures verify locally.
3. JS golden fixtures (generated with the shared 0x42 seed) verify in Python.
   Auto-skips with a clear message when the JS fixture directory is absent.
4. Byte-identity — each JS receipt, rebuilt with the Python SDK from its own
   inputs, reproduces the JS id, chain_hash, and signature.value exactly.
5. End-to-end ground truth — receipts built from RAW inputs (raw prompt/response
   strings + telemetry) reproduce the hashes the JS SDK published, proving the
   full pipeline (raw-string hashing included) matches, not just re-signing.
"""

import glob
import json
import os

import pytest

from sonate import (
    TrustReceipt,
    TrustReceipts,
    contract,
    crypto,
    get_public_key,
    verify_receipt,
)

SEED = "42" * 32
PUB = get_public_key(SEED)

PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY_FIXTURES = os.path.join(PKG_ROOT, "fixtures")
# The JS SDK lives beside this package in the same repository.
JS_FIXTURES = os.path.abspath(os.path.join(PKG_ROOT, "..", "trust-receipts", "fixtures"))


def _load_receipts(dir_path):
    """Return {basename: receipt_dict} for raw receipt fixtures in a directory."""
    out = {}
    for path in sorted(glob.glob(os.path.join(dir_path, "*.json"))):
        name = os.path.basename(path)
        if name in ("keys.json", "manifest.json"):
            continue
        with open(path, encoding="utf-8") as fh:
            out[name] = json.load(fh)
    return out


def _load_js_fixtures(dir_path):
    """Load JS golden fixtures, unwrapping the {public_key, receipt|receipts} format.

    Returns a list of ``(label, receipt_dict, public_key_hex)`` entries. Handles
    both raw receipts and the wrapper objects the JS generator emits.
    """
    entries = []
    for path in sorted(glob.glob(os.path.join(dir_path, "*.json"))):
        name = os.path.basename(path)
        if name in ("keys.json", "manifest.json"):
            continue
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        wrapper_pub = doc.get("public_key") if isinstance(doc, dict) else None
        if isinstance(doc, dict) and "receipts" in doc:
            for i, r in enumerate(doc["receipts"]):
                entries.append((f"{name}[{i}]", r, _receipt_pub(r, wrapper_pub)))
        elif isinstance(doc, dict) and "receipt" in doc:
            r = doc["receipt"]
            entries.append((name, r, _receipt_pub(r, wrapper_pub)))
        else:  # raw receipt
            entries.append((name, doc, _receipt_pub(doc, wrapper_pub)))
    return entries


def _receipt_pub(receipt, wrapper_pub):
    sig_pub = (receipt.get("signature") or {}).get("public_key")
    return sig_pub or wrapper_pub or PUB


def _pubkey_for(dir_path, fallback=PUB):
    """Resolve the public key for a fixture directory (keys.json, else fallback)."""
    keys_path = os.path.join(dir_path, "keys.json")
    if os.path.exists(keys_path):
        with open(keys_path, encoding="utf-8") as fh:
            keys = json.load(fh)
        return keys.get("public_key_hex") or keys.get("publicKey") or fallback
    return fallback


# ── 1. Independent construction from the contract primitives ─────────────

def test_hand_constructed_receipt_matches_class_and_verifies():
    """Build a receipt straight from the contract, with no help from the class."""
    interaction = {
        "model": "gpt-4",
        "provider": "openai",
        "prompt_hash": crypto.sha256_hex("What is the capital of France?"),
        "response_hash": crypto.sha256_hex("Paris."),
    }
    core = {
        "version": "2.2.0",
        "timestamp": "2026-01-01T00:00:00.000Z",
        "session_id": "session-1",
        "agent_did": "did:sonate:agent-1",
        "human_did": "did:sonate:human-1",
        "policy_version": "2.0.0",
        "mode": "constitutional",
        "interaction": interaction,
        "telemetry": {"resonance_score": 0.95, "overall_trust_score": 92},
        "chain": {"previous_hash": "GENESIS", "chain_hash": ""},
    }
    receipt_id = contract.generate_receipt_id(core)
    with_id = {**core, "id": receipt_id}
    chain_hash = contract.generate_chain_hash(with_id)
    for_sig = {**with_id, "chain": {**core["chain"], "chain_hash": chain_hash}}
    value = crypto.sign_detached(contract.canonicalize_for_signature(for_sig), SEED)
    hand = {
        **for_sig,
        "signature": {
            "algorithm": "Ed25519",
            "value": value,
            "key_version": "key_v1",
            "timestamp_signed": "2026-01-01T00:00:00.000Z",
        },
    }

    assert verify_receipt(hand, PUB).valid is True

    # The friendly class must produce the identical bytes for the same input.
    via_class = TrustReceipt(
        session_id="session-1",
        agent_did="did:sonate:agent-1",
        human_did="did:sonate:human-1",
        mode="constitutional",
        prompt="What is the capital of France?",
        response="Paris.",
        model="gpt-4",
        provider="openai",
        policy_version="2.0.0",
        telemetry={"resonance_score": 0.95, "overall_trust_score": 92},
        timestamp="2026-01-01T00:00:00.000Z",
    ).sign(SEED).to_json()

    assert via_class["id"] == hand["id"]
    assert via_class["chain"]["chain_hash"] == hand["chain"]["chain_hash"]
    assert via_class["signature"]["value"] == hand["signature"]["value"]


# ── 2. Python's own golden fixtures verify ───────────────────────────────

def test_python_fixtures_directory_exists():
    assert os.path.isdir(PY_FIXTURES), (
        "Python fixtures missing — run scripts/generate_fixtures.py"
    )
    assert _load_receipts(PY_FIXTURES), "No Python fixtures found"


@pytest.mark.parametrize("name", sorted(_load_receipts(PY_FIXTURES).keys()) or ["__none__"])
def test_python_fixture_verifies(name):
    receipts = _load_receipts(PY_FIXTURES)
    if name == "__none__":
        pytest.skip("No Python fixtures generated yet")
    result = verify_receipt(receipts[name], _pubkey_for(PY_FIXTURES))
    assert result.valid, f"{name} failed: {result.errors}"


def test_python_fixture_chain_links():
    receipts = _load_receipts(PY_FIXTURES)
    chain = [receipts[f"chain-{i}.json"] for i in range(3) if f"chain-{i}.json" in receipts]
    if len(chain) < 3:
        pytest.skip("chain fixtures not present")
    assert chain[0]["chain"]["previous_hash"] == "GENESIS"
    for prev, cur in zip(chain, chain[1:]):
        assert cur["chain"]["previous_hash"] == prev["chain"]["chain_hash"]


# ── 3. JS golden fixtures verify in Python (auto-skip if absent) ──────────

def _js_fixtures_available():
    return os.path.isdir(JS_FIXTURES) and bool(_load_js_fixtures(JS_FIXTURES))


_JS_ENTRIES = _load_js_fixtures(JS_FIXTURES) if os.path.isdir(JS_FIXTURES) else []


@pytest.mark.skipif(not _js_fixtures_available(), reason=f"JS fixtures not present at {JS_FIXTURES}")
@pytest.mark.parametrize("label", [e[0] for e in _JS_ENTRIES] or ["__none__"])
def test_js_fixture_verifies_in_python(label):
    entries = {e[0]: e for e in _load_js_fixtures(JS_FIXTURES)}
    _, receipt, pub = entries[label]
    result = verify_receipt(receipt, pub)
    assert result.valid, f"{label} failed Python verification: {result.errors}"


def _rebuild_with_python(js_receipt):
    """Re-derive a JS receipt's id/chain_hash/signature using the Python SDK.

    Uses the JS receipt's own inputs (including its interaction hashes) so the
    result must be byte-identical if both sides implement the contract correctly.
    """
    interaction = dict(js_receipt.get("interaction") or {})
    chain = js_receipt.get("chain") or {}
    sig = js_receipt.get("signature") or {}
    include_content = "prompt" in interaction or "response" in interaction
    rebuilt = TrustReceipt(
        session_id=js_receipt["session_id"],
        agent_did=js_receipt["agent_did"],
        human_did=js_receipt["human_did"],
        mode=js_receipt["mode"],
        interaction=interaction,
        telemetry=js_receipt.get("telemetry"),
        policy_state=js_receipt.get("policy_state"),
        policy_version=js_receipt.get("policy_version"),
        metadata=js_receipt.get("metadata"),
        previous_hash=chain.get("previous_hash", "GENESIS"),
        chain_length=chain.get("chain_length"),
        timestamp=js_receipt["timestamp"],
        key_version=sig.get("key_version", "key_v1"),
        include_content=include_content,
    )
    rebuilt.sign(SEED)
    return rebuilt.to_json()


# ── 4. Byte-identity of cryptographic fields across implementations ───────

@pytest.mark.skipif(not _js_fixtures_available(), reason=f"JS fixtures not present at {JS_FIXTURES}")
@pytest.mark.parametrize("label", [e[0] for e in _JS_ENTRIES] or ["__none__"])
def test_python_reproduces_js_receipt_byte_for_byte(label):
    """Rebuild each JS receipt with the Python SDK; the whole receipt must match.

    Both SDKs converge on the same signature-block shape
    ({algorithm, value, key_version, timestamp_signed}), so equality holds for the
    entire receipt object, not just the cryptographic fields.
    """
    entries = {e[0]: e for e in _load_js_fixtures(JS_FIXTURES)}
    _, js_receipt, _pub = entries[label]
    rebuilt = _rebuild_with_python(js_receipt)

    # Cryptographic fields.
    assert rebuilt["id"] == js_receipt["id"], f"{label}: id mismatch"
    assert rebuilt["chain"]["chain_hash"] == js_receipt["chain"]["chain_hash"], (
        f"{label}: chain_hash mismatch"
    )
    assert rebuilt["signature"]["value"] == js_receipt["signature"]["value"], (
        f"{label}: signature.value mismatch"
    )

    # Identical signature-block shape (team-lead requirement): no public_key,
    # timestamp_signed present and equal to the receipt timestamp.
    assert set(rebuilt["signature"]) == set(js_receipt["signature"]), (
        f"{label}: signature block keys differ: "
        f"py={sorted(rebuilt['signature'])} js={sorted(js_receipt['signature'])}"
    )
    assert rebuilt["signature"] == js_receipt["signature"], f"{label}: signature block mismatch"

    # Whole-object byte-for-byte identity under RFC 8785.
    assert crypto.canonicalize(rebuilt) == crypto.canonicalize(js_receipt), (
        f"{label}: full receipt canonical bytes differ"
    )


# ── 5. End-to-end ground truth against the JS SDK's published hashes ──────
#
# These hashes are the canonical output of the JavaScript SDK (committed golden
# fixtures, shared 0x42 seed, fixed timestamp). Building from RAW inputs and
# reproducing them proves the entire Python pipeline — including hashing raw
# prompt/response strings and assembling the signed payload — matches JS exactly.

GENESIS_EXPECTED = {
    "id": "4e25e38ea20588a9c49de09cfd9bc73fc577e926848faac7f6810ddd8aea783c",
    "chain_hash": "4147fd708d57a4c480aaa46e4fbf19526fe31cd7ed68d79cd3bf55de3f7d16a5",
    "signature": (
        "3aba9cf00ef2ce8d0e42a579554c94f95ef6b4612e78c0bc879d0a738b16a3e9"
        "72eac16414aa059c5ed4c2c37d3b54e670adcbaf58ce380d0b6b6c8c407e930e"
    ),
}

CHAIN_EXPECTED = [
    {
        "id": "82077d6af4aee1038109f6568f060787e305432e5f16b151df6ff7d79a423501",
        "chain_hash": "07658d45f2f55198bc43075dc1713b10d18ce8e676ffe505864a63e87acabcc4",
        "signature": (
            "056cd0907e3eae546177c6a0c8337c1ea2ffe4b38728a0a8f4bbc84ea57f51a0"
            "d87435344ffd296e07f26d92ecdc08dda808d124bb3fa9814673bb4e2a5b4d0b"
        ),
    },
    {
        "id": "270b5bc8d31d664a17b4b5d4748fe3062e3b0cb251c789a9875438b58faa4da6",
        "chain_hash": "9f019473862d25f7c2e91396cf4af100b85463652141e008ecda8ec44edf96e6",
        "signature": (
            "9d3f91320099f1f223dc9133e224936e832c067918d838863aa88df631dfc9bb"
            "d793c89b0a12261a89396b51f787dabd3a9fd22fc1e0296f1790f0432226f60b"
        ),
    },
    {
        "id": "c4194bdae36aac175ab2a0a76849945576b9028af5430994e1c1ea893a3fd154",
        "chain_hash": "7f859dfb39dd808089a31f1b59191f631dd296f19f8947fa28d30a96caeea5d2",
        "signature": (
            "c74f4fdac256dfd1f726bc0874528e64765e95baefd44a9a12b08b38154e78d7"
            "042fc10b2958f458b931081ef9becaeaa27b3aee8e01c278f84b24bda2a60409"
        ),
    },
]


def test_raw_build_reproduces_js_genesis_hashes():
    receipt = TrustReceipt(
        session_id="fixture-session-001",
        agent_did="did:sonate:gpt-4",
        human_did="did:sonate:anonymous",
        mode="constitutional",
        prompt="What is the capital of France?",
        response="The capital of France is Paris.",
        model="gpt-4",
        provider="openai",
        telemetry={"ciq_metrics": {"clarity": 0.95, "integrity": 0.9, "quality": 0.92}},
        chain_length=1,
        timestamp="2026-01-01T00:00:00.000Z",
    ).sign(SEED)
    data = receipt.to_json()
    assert data["id"] == GENESIS_EXPECTED["id"]
    assert data["chain"]["chain_hash"] == GENESIS_EXPECTED["chain_hash"]
    assert data["signature"]["value"] == GENESIS_EXPECTED["signature"]


def test_raw_build_reproduces_js_chain_hashes():
    sdk = TrustReceipts(
        private_key=SEED,
        default_agent_did="did:sonate:gpt-4",
        default_human_did="did:sonate:anonymous",
    )
    previous = None
    built = []
    for i in range(1, 4):
        receipt = sdk.create_receipt(
            session_id="fixture-chain-session",
            prompt=f"chain prompt {i}",
            response=f"chain response {i}",
            model="gpt-4",
            provider="openai",
            telemetry={"ciq_metrics": {"clarity": 0.9, "integrity": 0.9, "quality": 0.9}},
            previous_receipt=previous,
            timestamp="2026-01-01T00:00:00.000Z",
        )
        built.append(receipt)
        previous = receipt

    for i, (receipt, expected) in enumerate(zip(built, CHAIN_EXPECTED)):
        assert receipt["chain"]["chain_length"] == i + 1
        assert receipt["id"] == expected["id"], f"chain[{i}] id"
        assert receipt["chain"]["chain_hash"] == expected["chain_hash"], f"chain[{i}] chain_hash"
        assert receipt["signature"]["value"] == expected["signature"], f"chain[{i}] signature"
