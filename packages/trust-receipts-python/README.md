# sonate-trust-receipts (Python)

Generate and verify **SONATE v2.2.0 Trust Receipts** in Python — cryptographic,
tamper-evident audit records for AI interactions.

Receipts produced here are **byte-for-byte compatible** with the SONATE platform's
JavaScript implementation and verify with
[`@sonate/verify-sdk`](../verify-sdk); JavaScript-produced receipts verify here.
The compatibility is proven by a cross-language conformance test suite that
verifies JS golden fixtures in Python and reproduces their `id`, `chain_hash`, and
Ed25519 signature byte-for-byte.

- **Version 3.0.0** emits the v2.2.0 receipt format. See [Migration](#migration-from-1x--2x) if you used an earlier release.

## Install

```bash
pip install sonate-trust-receipts
```

Dependencies: [`PyNaCl`](https://pypi.org/project/PyNaCl/) (Ed25519) and
[`rfc8785`](https://pypi.org/project/rfc8785/) (RFC 8785 / JCS canonicalization,
matching `json-canonicalize` byte-for-byte).

## Quick start

```python
from sonate import TrustReceipts

# 32-byte Ed25519 seed as hex (keep this secret)
receipts = TrustReceipts(
    private_key="your-64-hex-char-seed",
    default_agent_did="did:sonate:my-agent",
    default_human_did="did:sonate:my-user",
)

response, receipt = receipts.wrap(
    lambda: call_your_model(prompt),      # any callable returning the model output
    session_id="user-123",
    input="Explain quantum computing.",
    model="gpt-4",
    provider="openai",
)

assert receipts.verify_receipt(receipt)   # local, zero-backend verification
print(receipt["id"])
```

`wrap()` runs your function, hashes the prompt and extracted response, and returns
the original response plus a signed receipt dict. It auto-extracts text from OpenAI
(`choices[0].message.content`) and Anthropic (`content[0].text`) response shapes;
pass `extract_response=...` for anything else.

## Building a receipt directly

```python
from sonate import TrustReceipt, verify_receipt, get_public_key

seed = "42" * 32
receipt = TrustReceipt(
    session_id="session-1",
    agent_did="did:sonate:agent-1",
    human_did="did:sonate:human-1",
    mode="constitutional",            # or "directive"
    prompt="What is the capital of France?",
    response="Paris.",
    model="gpt-4",
    provider="openai",
    policy_version="2.0.0",
    telemetry={"resonance_score": 0.95, "overall_trust_score": 92},
)
receipt.sign(seed)

data = receipt.to_json()
result = verify_receipt(data, get_public_key(seed))
print(result.valid, {k: c.passed for k, c in result.checks.items()})
```

### Privacy by default

Raw prompt/response text is **never** stored — only their SHA-256 hashes
(`interaction.prompt_hash` / `response_hash`). Pass `include_content=True` to embed
the raw text alongside the hashes.

### Hash chaining

Chain receipts to make the sequence tamper-evident. Each receipt's
`chain.previous_hash` points at the prior receipt's `chain.chain_hash`
(`"GENESIS"` for the first):

```python
r1 = receipts.create_receipt(session_id="s", prompt="a", response="1", model="m")
r2 = receipts.create_receipt(session_id="s", prompt="b", response="2", model="m",
                             previous_receipt=r1)
assert receipts.verify_chain([r1, r2])["valid"]
```

## Verification

`verify_receipt(receipt, public_key)` runs the same five checks as
`@sonate/verify-sdk`, entirely offline, and returns a `VerificationResult`:

| Check       | Meaning |
|-------------|---------|
| `structure` | `id` and `signature.value` present |
| `hash`      | recomputed receipt `id` matches |
| `signature` | Ed25519 signature verifies over the canonical receipt |
| `chain`     | `chain_hash` matches `sha256(canonical(chain_hash='') + previous_hash)` |
| `timestamp` | within the allowed age / future-skew window |

`quick_verify(...)` returns just the boolean.

## Receipt format (v2.2.0)

```jsonc
{
  "id": "sha256hex(canonical receipt without id/signature, chain_hash='')",
  "version": "2.2.0",
  "timestamp": "2026-01-01T00:00:00.000Z",
  "session_id": "…",
  "agent_did": "did:sonate:…",
  "human_did": "did:sonate:…",
  "policy_version": "2.0.0",           // optional
  "mode": "constitutional",            // or "directive"
  "interaction": {
    "prompt_hash": "…", "response_hash": "…",
    "model": "gpt-4", "provider": "openai"
  },
  "telemetry": { … },                  // optional trust metrics
  "chain": {
    "previous_hash": "GENESIS",
    "chain_hash": "sha256hex(canonical(chain_hash='') + previous_hash)",
    "chain_length": 1
  },
  "signature": {
    "algorithm": "Ed25519",
    "value": "hex(detached signature over canonical receipt without signature)",
    "key_version": "key_v1",
    "timestamp_signed": "2026-01-01T00:00:00.000Z"
  }
}
```

**Canonicalization** is RFC 8785 (JCS). Keys are omitted entirely when absent
(matching the JS side stripping `undefined`); explicit `null` inside `metadata` is
preserved. **Field ordering for hashing** is significant: the `id` is computed with
`chain_hash=""` and no `signature`; the `chain_hash` is computed with the real `id`
present and `chain_hash=""`; the signature covers the receipt with the real `id`
and `chain_hash` and no `signature` block.

**Keys** are 32-byte Ed25519 seeds; public keys are raw 32 bytes, both hex-encoded
(tweetnacl / `@noble/ed25519` semantics).

## Cross-language conformance

The test suite (`tests/test_conformance.py`) proves parity in both directions:

- JS golden fixtures under `packages/trust-receipts/fixtures/` verify in Python.
- Each JS receipt is rebuilt with the Python SDK and its `id`, `chain_hash`, and
  `signature.value` match byte-for-byte.
- Python golden fixtures (`scripts/generate_fixtures.py` → `fixtures/`) verify with
  the JS `@sonate/verify-sdk`.

Regenerate the Python fixtures with:

```bash
python scripts/generate_fixtures.py
```

## Migration from 1.x / 2.x

Version 3.0.0 is a breaking change: it replaces the legacy v1.0 snake_case receipt
(which was incompatible with the platform and `@sonate/verify-sdk`) with the
v2.2.0 contract.

| 1.x / 2.x | 3.0.0 |
|-----------|-------|
| `TrustReceiptData(...)` + `TrustReceipt(data)` | `TrustReceipt(session_id=..., agent_did=..., human_did=..., model=..., ...)` |
| `agent_id` | `agent_did` (bare ids are auto-prefixed `did:sonate:` — `agent_id=` still accepted) |
| `scores={...}` | `telemetry={...}` (a `scores=` alias merges into `telemetry`) |
| `prev_receipt_hash` | `chain.previous_hash` (`prev_receipt_hash=`/`previous_hash=` accepted) |
| `receipt.receipt_hash` | `receipt["id"]` (+ `receipt["chain"]["chain_hash"]`) |
| `await receipt.sign(key)` | `receipt.sign(key)` (synchronous) |
| `await receipts.wrap(fn, WrapOptions(...))` | `receipts.wrap(fn, session_id=..., input=..., model=...)` (synchronous, keyword args) |
| `SignedReceipt` dataclass | plain `dict` from `to_json()` |

The whole API is now synchronous — remove `await` and `asyncio`. Receipts are
plain dicts (JSON-ready), and verification is a standalone `verify_receipt()` (or
`receipts.verify_receipt()`).

## License

MIT
