#!/usr/bin/env python3
"""
Generate deterministic SONATE v2.2.0 golden fixtures from the Python SDK.

These fixtures use the cross-language conformance conventions agreed with the
JS side so that identical content produces byte-identical cryptographic fields:

- Ed25519 seed = 32 bytes of 0x42 (hex "42" * 32).
- Fixed ISO 8601 timestamps.
- key_version "key_v1"; signature.timestamp_signed = the receipt timestamp.
- Privacy-by-default interaction (prompt_hash/response_hash, no raw content),
  except the explicit include_content fixture.

Output: packages/trust-receipts-python/fixtures/*.json, plus keys.json (the seed
and derived public key) and manifest.json (index of fixtures).

Run:  python scripts/generate_fixtures.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)
sys.path.insert(0, PKG_ROOT)

from sonate import TrustReceipt, TrustReceipts, get_public_key  # noqa: E402

SEED = "42" * 32
PUBLIC_KEY = get_public_key(SEED)
FIXTURES_DIR = os.path.join(PKG_ROOT, "fixtures")

AGENT_DID = "did:sonate:agent-conformance-001"
HUMAN_DID = "did:sonate:human-conformance-001"


def _write(name: str, receipt: dict) -> None:
    path = os.path.join(FIXTURES_DIR, f"{name}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(receipt, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"  wrote {name}.json  (id={receipt['id'][:16]}...)")


def build() -> dict:
    os.makedirs(FIXTURES_DIR, exist_ok=True)
    written = {}

    # 1. Single constitutional receipt with telemetry + policy_version.
    single = TrustReceipt(
        session_id="session-conformance-001",
        agent_did=AGENT_DID,
        human_did=HUMAN_DID,
        mode="constitutional",
        prompt="What is the capital of France?",
        response="The capital of France is Paris.",
        model="gpt-4-turbo",
        provider="openai",
        policy_version="2.0.0",
        telemetry={
            "resonance_score": 0.95,
            "coherence_score": 0.91,
            "truth_debt": 0.02,
            "overall_trust_score": 92,
            "trust_status": "PASS",
            "ciq_metrics": {"clarity": 0.9, "integrity": 0.95, "quality": 0.88},
        },
        timestamp="2026-01-01T00:00:00.000Z",
    )
    single.sign(SEED)
    _write("single-constitutional", single.to_json())
    written["single-constitutional"] = "single-constitutional.json"

    # 2. Directive-mode minimal receipt (no telemetry / metadata / policy_version).
    minimal = TrustReceipt(
        session_id="session-conformance-002",
        agent_did=AGENT_DID,
        human_did=HUMAN_DID,
        mode="directive",
        prompt="Summarize this document.",
        response="Here is a concise summary.",
        model="claude-3-sonnet",
        provider="anthropic",
        timestamp="2026-01-02T12:30:45.123Z",
    )
    minimal.sign(SEED)
    _write("minimal-directive", minimal.to_json())
    written["minimal-directive"] = "minimal-directive.json"

    # 3. Unicode + metadata + policy_state, include_content=True (raw content kept).
    rich = TrustReceipt(
        session_id="session-conformance-003",
        agent_did=AGENT_DID,
        human_did=HUMAN_DID,
        mode="constitutional",
        prompt="Explain 世界 and 🌍 in one line.",
        response="Both refer to 'the world' — 世界 in Japanese/Chinese, 🌍 as the globe emoji.",
        model="gpt-4o",
        provider="openai",
        policy_version="2.1.0",
        policy_state={"consent_verified": True, "override_available": False},
        metadata={"tags": ["demo", "unicode"], "context": {"lang": "mixed"}},
        telemetry={"resonance_score": 0.8123456789, "bedau_index": 0.333},
        include_content=True,
        timestamp="2026-01-03T09:15:00.000Z",
    )
    rich.sign(SEED)
    _write("rich-unicode-content", rich.to_json())
    written["rich-unicode-content"] = "rich-unicode-content.json"

    # 4. Three-receipt chain (GENESIS -> r1 -> r2 -> r3).
    receipts = TrustReceipts(private_key=SEED, default_agent_did=AGENT_DID, default_human_did=HUMAN_DID)
    prev = None
    chain_ts = [
        "2026-02-01T00:00:00.000Z",
        "2026-02-01T00:00:01.000Z",
        "2026-02-01T00:00:02.000Z",
    ]
    for i, ts in enumerate(chain_ts):
        rec = receipts.create_receipt(
            session_id="session-conformance-chain",
            prompt=f"chain turn {i} prompt",
            response=f"chain turn {i} response",
            model="gpt-4",
            provider="openai",
            previous_receipt=prev,
            timestamp=ts,
            telemetry={"resonance_score": 0.5 + i * 0.1},
        )
        name = f"chain-{i}"
        _write(name, rec)
        written[name] = f"{name}.json"
        prev = rec

    # keys + manifest
    keys = {
        "algorithm": "Ed25519",
        "seed_hex": SEED,
        "seed_description": "32 bytes of 0x42",
        "public_key_hex": PUBLIC_KEY,
        "key_version": "key_v1",
    }
    with open(os.path.join(FIXTURES_DIR, "keys.json"), "w", encoding="utf-8") as fh:
        json.dump(keys, fh, indent=2)
        fh.write("\n")

    manifest = {
        "generator": "python",
        "sdk_version": "3.0.0",
        "receipt_version": "2.2.0",
        "public_key_hex": PUBLIC_KEY,
        "fixtures": written,
        "chain": ["chain-0.json", "chain-1.json", "chain-2.json"],
    }
    with open(os.path.join(FIXTURES_DIR, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")

    print(f"\nPublic key: {PUBLIC_KEY}")
    print(f"Wrote {len(written)} receipt fixtures + keys.json + manifest.json to {FIXTURES_DIR}")
    return written


if __name__ == "__main__":
    build()
