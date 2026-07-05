# @sonate/verify-sdk

[![npm version](https://img.shields.io/npm/v/@sonate/verify-sdk.svg)](https://www.npmjs.com/package/@sonate/verify-sdk)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Client-side SDK for verifying SONATE Trust Receipts. Works in Node.js and browsers — zero backend calls required.

## Install

```bash
npm install @sonate/verify-sdk
```

## Quick Start

```typescript
import { verify, fetchPublicKey } from '@sonate/verify-sdk';

// Fetch the SONATE public key (or provide your own)
const publicKey = await fetchPublicKey();

// Verify a receipt
const result = await verify(receipt, publicKey);

if (result.valid) {
  console.log('All checks passed');
  console.log('Trust score:', result.trustScore);
} else {
  console.error('Verification failed:', result.errors);
}
```

## API

### `verify(receipt, publicKey)`

Full verification with detailed check results.

```typescript
const result = await verify(receipt, publicKey);

// result.valid — overall pass/fail
// result.checks.structure — required fields present
// result.checks.signature — Ed25519 signature valid
// result.checks.chain — hash chain intact
// result.checks.timestamp — timestamp reasonable
// result.trustScore — extracted from telemetry (0-100)
// result.errors — array of error messages
```

### `quickVerify(receipt, publicKey)`

Boolean-only verification for simple pass/fail checks.

```typescript
const isValid = await quickVerify(receipt, publicKey);
```

### `verifyBatch(receipts, publicKey)`

Verify multiple receipts at once.

```typescript
const { total, valid, invalid, results } = await verifyBatch(receipts, publicKey);
```

### `fetchPublicKey(url?)`

Fetch a SONATE public key from a backend endpoint.

```typescript
// Default: fetches from SONATE platform
const key = await fetchPublicKey();

// Custom endpoint
const key = await fetchPublicKey('https://your-server.com/api/public-key');
```

### `canonicalize(obj)`

Deterministic JSON serialization via **RFC 8785 (JSON Canonicalization Scheme)** — it delegates to the [`json-canonicalize`](https://www.npmjs.com/package/json-canonicalize) library, with `undefined` values stripped first. This is the exact canonical form SONATE platform receipts are signed and chained over, so the verifier reproduces it byte-for-byte.

```typescript
import { canonicalize } from '@sonate/verify-sdk';

const canonical = canonicalize({ b: 2, a: 1 });
// '{"a":1,"b":2}'
```

> **Note:** The SDK, the platform receipt generator, and `@sonate/trust-receipts` all canonicalize the same way (RFC 8785), so a receipt produced by any of them verifies here without a canonicalization mismatch.

## Verification Checks

| Check | What it verifies |
|-------|-----------------|
| **Structure** | Receipt has the required `id` and `signature` fields (V2 format) |
| **Hash** | `id` matches `SHA-256` of the canonical receipt payload — the content hasn't been altered |
| **Signature** | Ed25519 signature over the canonical receipt content |
| **Chain** | `chain_hash` matches `SHA-256(canonical_content + previous_hash)` |
| **Timestamp** | Not in the future (5-min skew), not older than `maxAgeMs` (default 1 year) |

> **Scope:** these checks prove a receipt is **authentic and untampered** — it was signed
> by the holder of the key and nothing has been changed since. They do **not** re-derive the
> trust score; `result.trustScore` is read from the signed payload (authentic as issued).

## Browser Support

The SDK uses Web Crypto API in browsers and falls back to Node.js `crypto` module. Ed25519 operations use `@noble/ed25519` for cross-platform compatibility.

```html
<script type="module">
  import { verify, fetchPublicKey } from '@sonate/verify-sdk';

  const publicKey = await fetchPublicKey();
  const result = await verify(receiptFromAPI, publicKey);
  console.log('Valid:', result.valid);
</script>
```

## Receipt Format

The SDK verifies V2 Trust Receipts:

```typescript
interface TrustReceipt {
  id: string;              // SHA-256 of canonical content
  version: '2.0.0' | '2.2.0';
  timestamp: string;       // ISO 8601
  session_id: string;
  agent_did: string;       // did:web:...
  human_did: string;
  mode: 'constitutional' | 'directive';
  interaction: {
    prompt?: string;        // Raw content (when included)
    response?: string;
    prompt_hash?: string;   // SHA-256 hash (privacy-preserving)
    response_hash?: string;
    model: string;
  };
  chain: {
    previous_hash: string;
    chain_hash: string;
  };
  signature: {
    algorithm: 'Ed25519';
    value: string;          // Hex-encoded
    key_version: string;
  };
}
```

## FAQ

### What is a Trust Receipt?

A cryptographically signed, hash-chained record of an AI interaction. It proves a canonical representation of the payload, the governance result, chain linkage to prior receipts, and the signer identity. Anyone can verify a receipt independently with this SDK — no vendor trust required.

### How is this different from logs?

Logs are mutable, vendor-controlled, and not independently verifiable. A Trust Receipt is signed with Ed25519, canonicalized deterministically, and chained to prior receipts so tampering with any field causes verification to fail. Logs describe what was said. Receipts prove it.

### Can I verify a receipt without using the SONATE platform?

Yes — that's the point. This SDK is MIT licensed and runs verification entirely client-side (zero backend calls). If you needed our servers to confirm a receipt, it would just be another log. You supply the receipt and a public key; verification is local.

### Does verifying a receipt prove the AI's trust score is correct?

No. Verification proves the receipt is **authentic and untampered** (signature, hash, chain, timestamp). The trust/telemetry scores are read from the signed payload as issued — this SDK does not re-run the governance kernel or re-derive scores. Independent re-computation of the decision is a separate, server-side capability.

### What is the relationship between SYMBI and SONATE?

SONATE is the production trust infrastructure — signed receipts, governance, audit evidence. SYMBI is the experimental access and participation layer that explores public-facing interaction with the system. The two are intentionally separate. SONATE is monetised via SaaS; SYMBI is not a financial product.

### What is open and what is proprietary?

The Trust Receipt schema is open and this verify SDK is MIT licensed. The SONATE platform — orchestration, detection, scoring kernel, dashboards, hosted services — is proprietary to Yseeku Pty Ltd. Independent verification stays open by design.

## Related Packages

- [`@sonate/trust-receipts`](https://www.npmjs.com/package/@sonate/trust-receipts) — Generate signed receipts in your own applications
- [`@sonate/schemas`](https://www.npmjs.com/package/@sonate/schemas) — JSON Schema + TypeScript types
- [`@sonate/core`](https://www.npmjs.com/package/@sonate/core) — Core trust protocol implementation

## License

MIT
