# SONATE-SDK

Public SDK workspace for integrating with SONATE Trust Receipts.

SONATE gives developers a way to make AI interactions cryptographically verifiable:
- generate signed receipts for model outputs
- verify signatures and hash-chain integrity offline
- validate receipt structure against a shared schema

## What Is Public

This repository contains the public integration and verification surface:
- [`@sonate/trust-receipts`](https://www.npmjs.com/package/@sonate/trust-receipts) — generate signed receipts in your app
- [`@sonate/verify-sdk`](https://www.npmjs.com/package/@sonate/verify-sdk) — verify receipts in Node.js or the browser
- [`@sonate/schemas`](https://www.npmjs.com/package/@sonate/schemas) — shared JSON Schema and TypeScript types

## What Is Not Public

The verification layer is intentionally open.
The enforcement engine is proprietary.

That split is deliberate:
- developers, auditors, and counterparties should be able to inspect and verify receipt integrity independently
- SONATE's internal scoring, policy packs, kernel logic, runtime evidence layer, and governance orchestration remain private product IP

This is the same design principle used in other infrastructure products: the interface is open, the decision engine is not.

## Quick Start

Install the public packages you need:

```bash
npm install @sonate/trust-receipts @sonate/verify-sdk @sonate/schemas
```

### 1. Generate A Receipt

```ts
import { TrustReceipts } from "@sonate/trust-receipts";

const receipts = new TrustReceipts({
  privateKey: process.env.SONATE_PRIVATE_KEY!,
});

const { response, receipt } = await receipts.wrap(
  () => model.complete("Explain zero-knowledge proofs."),
  {
    sessionId: "session-123",
    input: "Explain zero-knowledge proofs.",
  }
);
```

### 2. Verify A Receipt

```ts
import { fetchPublicKey, verify } from "@sonate/verify-sdk";

const publicKey = await fetchPublicKey();
const result = await verify(receipt, publicKey);

console.log(result.valid);
console.log(result.errors);
```

### 3. Validate The Shape

```ts
import { receiptValidator } from "@sonate/schemas";

const validation = receiptValidator.validateJSON(receipt);
console.log(validation.valid);
```

## Package Guide

### `@sonate/trust-receipts`

Use this when you want to:
- wrap model calls
- sign receipts with Ed25519
- hash-chain multi-turn conversations
- anchor receipt hashes into your own audit flow

See: [`packages/trust-receipts`](./packages/trust-receipts)

### `@sonate/verify-sdk`

Use this when you want to:
- verify receipts offline
- validate signatures and chain continuity
- fetch a public key from a verification endpoint
- run receipt checks in a browser or Node.js

See: [`packages/verify-sdk`](./packages/verify-sdk)

### `@sonate/schemas`

Use this when you want to:
- share receipt types across services
- validate receipt payloads with JSON Schema
- build your own tooling around the receipt format

See: [`packages/schemas`](./packages/schemas)

## Recommended Adoption Pattern

For most teams:
1. Start with `@sonate/trust-receipts` in the app that produces model outputs.
2. Add `@sonate/verify-sdk` anywhere that needs independent verification.
3. Use `@sonate/schemas` in shared tooling, ingestion pipelines, or compliance workflows.

## Repository Structure

```text
SONATE-SDK/
├── packages/
│   ├── schemas/
│   ├── trust-receipts/
│   └── verify-sdk/
```

## Philosophy

SONATE is designed so that verification does not require trusting SONATE.

You can inspect the receipt format, validate the schema, and verify the signatures yourself.
What stays private is the internal enforcement and governance engine that decides how a system should respond to risky behavior.

## License

MIT
