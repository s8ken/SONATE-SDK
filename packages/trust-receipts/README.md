# @sonate/trust-receipts

[![npm version](https://img.shields.io/npm/v/@sonate/trust-receipts.svg)](https://www.npmjs.com/package/@sonate/trust-receipts)
[![tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/s8ken/SONATE-SDK)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Advanced local and self-managed receipt tooling for teams that want to sign and chain receipts outside the hosted SONATE platform.**

As of **v3.0.0**, this package produces **SONATE v2.2.0 receipts** that verify successfully with [`@sonate/verify-sdk`](https://www.npmjs.com/package/@sonate/verify-sdk). Receipts you sign locally are now cryptographically interoperable with the official verifier and the hosted platform. See [Migrating from 2.x](#migrating-from-2x) if you are upgrading.

If you want the default SONATE integration path, use [`@sonate/sdk`](https://www.npmjs.com/package/@sonate/sdk) instead. That package sends interactions to SONATE, returns constitutional scores and kernel verdicts, and gives you a signed verification URL back immediately.

## The Problem

AI systems generate outputs that need to be auditable. Who said what? When? Was the response tampered with? Current logging is trust-based and easily manipulated.

## The Solution

Trust Receipts work like SSL certificates for AI interactions:

- **Authentication**: Ed25519 signatures prove who generated the receipt
- **Integrity**: SHA-256 hashes of prompt and response detect tampering
- **Non-repudiation**: Hash chains create tamper-evident audit trails — any modification causes verification to fail

## Install

```bash
npm install @sonate/trust-receipts
```

## When To Use This Package

Choose packages by integration style:

- **Hosted SONATE platform:** use [`@sonate/sdk`](https://www.npmjs.com/package/@sonate/sdk)
- **Independent verification in browser/Node:** use [`@sonate/verify-sdk`](https://www.npmjs.com/package/@sonate/verify-sdk)
- **Shared receipt types/schema validation:** use [`@sonate/schemas`](https://www.npmjs.com/package/@sonate/schemas)
- **Local/self-managed signing:** use `@sonate/trust-receipts`

## Quick Start

```typescript
import { TrustReceipts } from '@sonate/trust-receipts';
import OpenAI from 'openai';

const receipts = new TrustReceipts({
  privateKey: process.env.SONATE_PRIVATE_KEY, // 32-byte Ed25519 seed (hex)
});

const openai = new OpenAI();
const messages = [{ role: 'user', content: 'Explain quantum computing.' }];

const { response, receipt } = await receipts.wrap(
  () => openai.chat.completions.create({ model: 'gpt-4', messages }),
  { sessionId: 'user-123', input: messages, provider: 'openai' }
);

console.log(response.choices[0].message.content);
console.log('Receipt id:', receipt.id);
console.log('Signature:', receipt.signature.value);
```

## Verify with @sonate/verify-sdk (round-trip)

Every receipt produced by this SDK verifies with the official verifier:

```typescript
import { TrustReceipts } from '@sonate/trust-receipts';
import { verify } from '@sonate/verify-sdk';

const receipts = new TrustReceipts();
const publicKey = await receipts.getPublicKey(); // hex

const { receipt } = await receipts.wrap(
  async () => ({ choices: [{ message: { content: 'Paris.' } }] }),
  { sessionId: 's1', input: 'Capital of France?', provider: 'openai' }
);

const result = await verify(receipt, publicKey);
console.log(result.valid);            // true
console.log(result.checks.signature); // { passed: true, ... }
console.log(result.checks.hash);      // { passed: true, ... }  (receipt id)
console.log(result.checks.chain);     // { passed: true, ... }
```

## Receipt Structure (SONATE v2.2.0)

```typescript
interface SonateReceipt {
  id: string;                 // SHA-256 hex of the canonical receipt content
  version: '2.2.0';
  timestamp: string;          // ISO 8601 UTC
  session_id: string;
  agent_did: string;          // e.g. "did:sonate:gpt-4"
  human_did: string;          // e.g. "did:sonate:anonymous"
  policy_version?: string;
  mode: 'constitutional' | 'directive';
  interaction: {
    prompt?: string;          // present only when includeContent: true
    response?: string;        // present only when includeContent: true
    prompt_hash: string;      // SHA-256 of the prompt
    response_hash: string;    // SHA-256 of the response
    model: string;
    provider?: string;
  };
  telemetry?: {
    ciq_metrics?: { clarity?: number; integrity?: number; quality?: number };
    custom_scores?: Record<string, number>;
    // ...any additional telemetry fields you pass through
  };
  chain: {
    previous_hash: string;    // 'GENESIS' for the first receipt
    chain_hash: string;
    chain_length?: number;
  };
  signature: {
    algorithm: 'Ed25519';
    value: string;            // hex signature
    key_version: string;
    timestamp_signed?: string; // set to the receipt timestamp (metadata outside the signed bytes)
  };
  metadata?: Record<string, unknown>;
}
```

### How the receipt is built (cryptographic contract)

Canonicalization uses [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) (`json-canonicalize`) with `undefined` values stripped first — byte-for-byte identical to `@sonate/verify-sdk`. Construction order:

1. **Build the base** receipt (no `id`, `chain.chain_hash = ''`, no `signature`).
2. **`id`** = `sha256hex(canonical(receipt without signature, without id, chain_hash=''))`.
3. **`chain.chain_hash`** = `sha256hex(canonical(receipt without signature, chain_hash='', with id) + previous_hash)`.
4. **`signature.value`** = Ed25519 over the utf-8 bytes of `canonical(receipt without signature)` — with the real `id` and `chain_hash` present.

> **Security — the `signature` block is unsigned metadata.** The entire `signature` object is stripped before the id/chain/signature hashes are computed (matching the SONATE platform reference), so `signature.key_version` and `signature.timestamp_signed` are **not** covered by the signature and must not be trusted. In particular, **never select the verification public key from receipt contents** — always obtain the public key from a trusted external source (a pinned key, a `.well-known` endpoint, or a DID document). `verify()` requires you to pass that key in for exactly this reason.

## Developer inputs map onto the wire format

The developer-facing API stays ergonomic; legacy camelCase inputs are mapped onto v2.2.0:

| Input (`TrustReceiptData` / `WrapOptions`) | Receipt field |
|---|---|
| `sessionId` | `session_id` |
| `agentId` (string) | `agent_did` (prefixed `did:sonate:` if not already a DID) + `interaction.model` |
| `agentDid` | `agent_did` (verbatim) |
| `humanId` / `humanDid` | `human_did` (default `did:sonate:anonymous`) |
| `model` / `provider` | `interaction.model` / `interaction.provider` |
| `mode` | `mode` (default `constitutional`) |
| `scores.{clarity,integrity,quality}` | `telemetry.ciq_metrics` |
| other `scores` keys | `telemetry.custom_scores` |
| `prevReceiptHash` / `previousReceipt` | `chain.previous_hash` |
| `includeContent: true` | `interaction.prompt` + `interaction.response` (plus hashes) |
| `metadata` | `metadata` |

## Key Generation

```typescript
// Generate a new key pair (hex strings)
const { privateKey, publicKey } = await TrustReceipts.generateKeyPair();

console.log('Private Key:', privateKey); // 32-byte Ed25519 seed — store securely!
console.log('Public Key:', publicKey);   // Share for verification
```

## Hash Chaining

Link receipts for a tamper-evident audit trail:

```typescript
const { receipt: r1 } = await receipts.wrap(call1, { sessionId: 's1', input: q1 });
const { receipt: r2 } = await receipts.wrap(call2, {
  sessionId: 's1',
  input: q2,
  previousReceipt: r1, // chains r2.chain.previous_hash to r1.chain.chain_hash
});

// r2.chain.previous_hash === r1.chain.chain_hash
```

## Verification

```typescript
// Verify a single receipt (signature + id + chain integrity)
const valid = await receipts.verifyReceipt(receipt, publicKey);

// Verify an entire chain (signatures + linkage)
const result = await receipts.verifyChain([r1, r2, r3], publicKey);
console.log(result.valid);   // true if all signatures and links valid
console.log(result.errors);  // Array of any errors found
```

## Scores & Attestation

Scores are **user-defined attestation values** — the SDK does not compute them. `clarity`, `integrity`, and `quality` are mapped to `telemetry.ciq_metrics` (which `@sonate/verify-sdk` uses to compute a trust score); any other keys are preserved under `telemetry.custom_scores`.

```typescript
const { receipt } = await receipts.wrap(aiCall, {
  sessionId: 'session-1',
  input: messages,
  scores: {
    clarity: 0.95,     // -> telemetry.ciq_metrics.clarity
    integrity: 0.9,    // -> telemetry.ciq_metrics.integrity
    quality: 0.88,     // -> telemetry.ciq_metrics.quality
    safety: 0.99,      // -> telemetry.custom_scores.safety
  },
});
```

For computed scores, provide a `calculateScores` function on the constructor.

## Privacy

By default, only SHA-256 hashes of prompt and response are included (`interaction.prompt_hash` / `interaction.response_hash`). Original content is never stored unless you opt in with `includeContent: true`, which additionally populates `interaction.prompt` and `interaction.response`.

```typescript
// Default: hashes only (privacy-preserving)
const { receipt } = await receipts.wrap(aiCall, { sessionId: 's1', input: messages });
// receipt.interaction.prompt_hash = "a1b2c3..."
// receipt.interaction.prompt      = undefined

// Opt-in: include full content
const { receipt: full } = await receipts.wrap(aiCall, {
  sessionId: 's1',
  input: messages,
  includeContent: true,
});
// full.interaction.prompt   = "..."
// full.interaction.response = "..."
```

## Streaming Support

For streaming responses, create receipts manually after accumulating the response:

```typescript
let fullResponse = '';
for await (const event of stream) fullResponse += event.text;

const receipt = await receipts.createReceipt({
  sessionId: 'stream-session',
  prompt: messages,
  response: fullResponse,
  provider: 'anthropic',
  previousReceipt: lastReceipt,
  scores: { completeness: 0.95 },
});
```

## Bitcoin Anchoring (OpenTimestamps)

For stronger timestamp guarantees, anchor the receipt `id` to Bitcoin:

```typescript
import { TrustReceipts, anchor, upgradeAnchor } from '@sonate/trust-receipts';

const { receipt } = await receipts.wrap(aiCall, { sessionId: 's1', input });

const proof = await anchor(receipt.id);           // submit to calendar servers
const upgraded = await upgradeAnchor(proof);      // later: check Bitcoin confirmation
```

Since receipts are hash-chained, anchoring the final receipt transitively anchors the whole conversation via `anchorChain([...ids])`.

## Golden fixtures & cross-language conformance

Deterministic golden receipts (fixed key seed, fixed timestamps, fixed content) live in [`fixtures/`](./fixtures) and are regenerated with:

```bash
npm run generate:fixtures --workspace=@sonate/trust-receipts
```

Each fixture is verified by `@sonate/verify-sdk` in this package's test suite, and the same bytes are verified by the Python SDK for true cross-language conformance.

## Migrating from 2.x

v3.0.0 is a **breaking format change**: receipts are now SONATE **v2.2.0** instead of the legacy `1.0` camelCase format.

**Receipt shape changed** (snake_case, DID identities, structured `interaction`/`chain`/`signature`):

| 2.x field | 3.0 field |
|---|---|
| `receipt.receiptHash` | `receipt.id` |
| `receipt.sessionId` | `receipt.session_id` |
| `receipt.agentId` | `receipt.agent_did` (a DID) + `receipt.interaction.model` |
| `receipt.promptHash` / `responseHash` | `receipt.interaction.prompt_hash` / `response_hash` |
| `receipt.scores` | `receipt.telemetry.ciq_metrics` / `telemetry.custom_scores` |
| `receipt.prevReceiptHash` | `receipt.chain.previous_hash` |
| `receipt.signature` (string) | `receipt.signature.value` (hex) inside a signature object |
| `receipt.version === '1.0'` | `receipt.version === '2.2.0'` |

**What did *not* change** — the developer-facing API is preserved: `new TrustReceipts({...})`, `wrap()`, `createReceipt()`, `verifyReceipt()`, `verifyChain()`, `TrustReceipt`, `TrustReceipt.fromJSON()`, key generation, and the `anchor` / `upgradeAnchor` / `verifyAnchor` / `anchorChain` exports all keep the same call signatures. You mostly need to update code that reads receipt fields.

**Signing input changed**: 2.x signed the receipt hash bytes; 3.0 signs the utf-8 bytes of the canonical receipt (matching `@sonate/verify-sdk`). Receipts signed by 2.x will **not** verify under 3.0 and vice versa — re-issue receipts you need to keep verifiable.

**New optional inputs**: `provider`, `model`, `mode`, `humanId` / `humanDid`, `agentDid`, `policyVersion`, and a `timestamp` override for deterministic fixtures.

## Cryptographic Details

| Component | Specification |
|-----------|--------------|
| Receipt format | SONATE v2.2.0 |
| Signing | Ed25519 (RFC 8032) over canonical receipt bytes |
| Hashing | SHA-256 |
| Canonicalization | JSON Canonicalization Scheme (RFC 8785), `undefined` stripped |
| Key Size | 32 bytes (256-bit Ed25519 seed) |
| Signature Size | 64 bytes (hex-encoded) |
| Timestamp | ISO 8601 UTC |
| Anchoring | OpenTimestamps (Bitcoin) |

## Related Packages

- **[`@sonate/sdk`](https://www.npmjs.com/package/@sonate/sdk)** — Official platform SDK for evaluating interactions and receiving signed receipts
- **[`@sonate/verify-sdk`](https://www.npmjs.com/package/@sonate/verify-sdk)** — Local cryptographic verification (the normative verifier for this format)
- **[`@sonate/schemas`](https://www.npmjs.com/package/@sonate/schemas)** — JSON Schema + TypeScript types for Trust Receipts

## License

MIT
