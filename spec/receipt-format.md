# SONATE Trust Receipt format, v2.2.0

A trust receipt is a signed JSON record of one AI interaction or agent decision.
It lets anyone holding the producer's public key check, offline, that the record
has not been changed since it was signed, and where it sits in the producer's
hash chain.

This document describes the format the code in this repository produces and
verifies. The JSON Schema in
[`packages/schemas/src/receipt.schema.json`](../packages/schemas/src/receipt.schema.json)
is the machine-readable source for field types.

## 1. Structure

```jsonc
{
  "id": "5d16f506…",                    // sha256 hex of the canonical receipt (§3)
  "version": "2.2.0",
  "timestamp": "2026-11-21T10:00:00.000Z",
  "session_id": "session-42",
  "agent_did": "did:sonate:refund-agent",
  "human_did": "did:sonate:anonymous",
  "mode": "constitutional",             // or "directive"
  "interaction": {
    "prompt_hash": "9f86d081…",         // sha256 hex of the input
    "response_hash": "60303ae2…",       // sha256 hex of the output
    "model": "example-model",
    "provider": "openai"                // optional
  },
  "telemetry": { "ciq_metrics": { "clarity": 0.9 } },   // optional
  "chain": {
    "previous_hash": "GENESIS",         // or the previous receipt's chain_hash
    "chain_hash": "bb585569…",
    "chain_length": 1                   // optional
  },
  "signature": {
    "algorithm": "Ed25519",
    "value": "056cd090…",               // 64-byte signature, hex
    "key_version": "key_v1",
    "timestamp_signed": "2026-11-21T10:00:00.000Z"   // optional
  },
  "metadata": {}                        // optional
}
```

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | 64 lowercase hex characters. Content address of the receipt (§3). |
| `version` | yes | `2.2.0` for receipts produced by these SDKs. The schema also accepts legacy `2.0.0`. |
| `timestamp` | yes | ISO 8601 UTC. Asserted by the producer (§7). |
| `session_id` | yes | Producer-defined grouping key. |
| `agent_did`, `human_did` | yes | DIDs. The SDKs prefix bare identifiers with `did:sonate:`. |
| `mode` | yes | `constitutional` or `directive`. |
| `interaction` | yes | `model` is required. `prompt_hash` and `response_hash` are always present in v2.2.0 output. |
| `interaction.prompt`, `interaction.response` | no | Plaintext, only when the producer opts in (§6). |
| `chain` | yes | `previous_hash` and `chain_hash`; `chain_length` optional. |
| `signature` | yes | `algorithm` is `Ed25519`; `value` is hex. |
| `telemetry`, `policy_state`, `metadata`, `policy_version` | no | Signed but not interpreted by verifiers (§8). |

## 2. Canonicalization

Every hash and signature is computed over the
[RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
serialization of a JSON object, after removing keys whose value is `undefined`
(they have no JSON representation). The JavaScript SDKs use
`json-canonicalize` 2.0.0 and the Python SDK uses `rfc8785`; the conformance
tests check that both produce identical bytes (§10).

`sha256hex(x)` below means the lowercase hex SHA-256 of the UTF-8 bytes of `x`.

## 3. Construction

A producer builds the receipt without `id`, `chain.chain_hash` or `signature`,
then fills them in this order:

1. **id**
   `id = sha256hex(canonical(R))`, where `R` is the receipt with no `signature`,
   no `id`, and `chain.chain_hash` set to `""`.
2. **chain_hash**
   `chain_hash = sha256hex(canonical(R') + previous_hash)`, where `R'` is the
   receipt with no `signature` and `chain.chain_hash` set to `""` (`id` is
   present). `previous_hash` is the previous receipt's `chain_hash`, or the
   string `GENESIS` for the first receipt in a chain. An empty `previous_hash`
   is treated as `GENESIS`.
3. **signature**
   `signature.value = hex(Ed25519_sign(privateKey, utf8(canonical(R''))))`, where
   `R''` is the receipt with no `signature` block. `id` and the final
   `chain_hash` are present, so the signature covers both.

The whole `signature` block is excluded from all three inputs. Fields inside it,
such as `timestamp_signed` and `key_version`, are therefore not covered by the
signature.

## 4. Verification

Given a receipt and the producer's Ed25519 public key (32 bytes, hex),
`@sonate/verify-sdk` runs five checks. A receipt is **valid** only if all five
pass.

| Check | Passes when |
| --- | --- |
| `structure` | `id` and `signature.value` are present. |
| `hash` | Recomputing step 1 gives exactly `id`. |
| `signature` | The Ed25519 signature over step 3's input verifies with the public key. |
| `chain` | Recomputing step 2 gives exactly `chain.chain_hash`. A first receipt (`previous_hash: "GENESIS"`) with no `chain_hash` also passes. |
| `timestamp` | `timestamp` is no more than 5 minutes in the future and no older than the maximum age (default 1 year; configurable). |

Checking a single receipt does not check its neighbours. To verify a chain,
also check that each receipt's `chain.previous_hash` equals the `chain_hash` of
the receipt before it, and that the first one is `GENESIS`.

## 5. Hash chains

Each receipt commits to the previous receipt's `chain_hash`. Inserting,
removing or reordering receipts breaks a link that a verifier can detect. A
chain belongs to one producer key; the hosted SONATE platform keeps a separate
chain per tenant.

A chain is tamper-evident, not tamper-proof: a producer that holds the private
key can re-sign a different history. Anchoring receipt hashes externally (the
TypeScript SDK includes optional OpenTimestamps anchoring) or sharing them with
a counterparty as they are created limits this.

## 6. Privacy

By default a receipt contains only `prompt_hash` and `response_hash`. Each is
`sha256hex` of the value if it is a string, or of its canonical JSON otherwise;
a missing value hashes the empty string. Plaintext `prompt` and `response`
appear only if the producer opts in (`includeContent: true` in TypeScript).

A hash of short or guessable text can be reversed by trying candidates, so
hash-only receipts protect content from casual disclosure, not from someone who
can guess it.

## 7. Keys and discovery

- Keys are Ed25519. The private key is a 32-byte seed; the public key is 32
  bytes. Both are exchanged as hex.
- `signature.key_version` labels the key that signed the receipt so producers
  can rotate keys. It is not covered by the signature (§3).
- The verifier needs the public key from a source it trusts. For receipts from
  the hosted SONATE platform, `fetchPublicKey()` in `@sonate/verify-sdk` reads
  `https://yseeku-backend.fly.dev/.well-known/sonate-pubkey.json`; for receipts
  you produce yourself, distribute your own public key.
- `timestamp` is asserted by the producer, not by a trusted clock. Use external
  anchoring if you need independent proof of time.

## 8. Telemetry, policy state and metadata

`telemetry`, `policy_state`, `policy_version` and `metadata` are covered by the
id, chain hash and signature, so they cannot be changed undetected. Verifiers do
not interpret them: a valid signature proves the producer recorded these values,
not that they are correct.

## 9. What a valid receipt proves

**It proves** that the holder of the private key signed this exact record:
these input and output hashes, this model, session and agent, these metrics,
at this position in the chain, and that nothing covered by the signature has
changed since.

**It does not prove** that the model actually produced that output, that the
metrics are accurate, that the timestamp is true, or that the producer did not
also keep a different chain. Receipts make a producer's claims checkable and
attributable; they do not make the claims true.

## 10. Conformance

Golden fixtures, all generated from a fixed test seed (32 bytes of `0x42`, never
used for real signing):

- JavaScript: [`packages/trust-receipts/fixtures`](../packages/trust-receipts/fixtures)
- Python: [`packages/trust-receipts-python/fixtures`](../packages/trust-receipts-python/fixtures)

The test suites check them across languages: Python verifies the JavaScript
receipts and reproduces them byte for byte, and `@sonate/verify-sdk` verifies the
Python receipts. An independent implementation should do the same.
