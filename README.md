# SONATE-SDK

Public SDK workspace for integrating with SONATE platform receipts and verification.

SONATE gives developers a way to make AI interactions cryptographically verifiable:
- send interactions to SONATE and receive signed governance receipts
- generate signed receipts for model outputs
- verify signatures and hash-chain integrity offline
- validate receipt structure against a shared schema

## What Is Public

This repository contains the public integration and verification surface:
- [`@sonate/sdk`](https://www.npmjs.com/package/@sonate/sdk) — official platform client for evaluating interactions and receiving signed receipts
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
npm install @sonate/sdk
```

### 1. Evaluate An Interaction

```ts
import { SonateClient } from "@sonate/sdk";

const sonate = new SonateClient({
  apiKey: process.env.SONATE_API_KEY!,
});

const evaluation = await sonate.evaluate({
  sessionId: "session-123",
  model: "gpt-4o-mini",
  prompt: "Explain zero-knowledge proofs.",
  response: "Zero-knowledge proofs let one party prove a statement without revealing the secret itself."
});

console.log(evaluation.status);
console.log(evaluation.receiptHash);
console.log(evaluation.verificationUrl);
```

### 2. Wrap An Existing Model Call

```ts
import OpenAI from "openai";
import { SonateClient } from "@sonate/sdk";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const sonate = new SonateClient({ apiKey: process.env.SONATE_API_KEY! });

const { result, evaluation } = await sonate.wrap(
  () =>
    openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "Explain zero-knowledge proofs." }],
    }),
  {
    sessionId: "session-123",
    prompt: "Explain zero-knowledge proofs.",
    model: "gpt-4o-mini",
    provider: "openai",
  }
);

console.log(result.choices[0].message.content);
console.log(evaluation.kernelSummary);
```

### 3. Verify A Receipt

```ts
import { fetchPublicKey, verify } from "@sonate/verify-sdk";

const publicKey = await fetchPublicKey();
const result = await verify(evaluation.receipt, publicKey);

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

### `@sonate/sdk`

Use this when you want to:
- send interactions to the SONATE platform
- receive constitutional scores, kernel verdicts, and signed receipts
- wrap existing model calls with one client
- integrate with the public verifier flow

See: [`packages/sdk`](./packages/sdk)

### `@sonate/trust-receipts`

Use this when you want to:
- generate receipts locally
- sign receipts with Ed25519
- hash-chain multi-turn conversations
- anchor receipt hashes into your own audit flow
- build self-managed or hybrid attestation flows

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
1. Start with `@sonate/sdk` to send interactions to SONATE and receive a signed receipt.
2. Add `@sonate/verify-sdk` anywhere that needs independent verification.
3. Use `@sonate/schemas` in shared tooling, ingestion pipelines, or compliance workflows.
4. Only use `@sonate/trust-receipts` if you specifically need self-managed receipt generation.

## Repository Structure

```text
SONATE-SDK/
├── packages/
│   ├── sdk/
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
