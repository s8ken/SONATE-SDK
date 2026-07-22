# @sonate/schemas

[![npm version](https://img.shields.io/npm/v/@sonate/schemas.svg)](https://www.npmjs.com/package/@sonate/schemas)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Shared schema definitions for SONATE Trust Receipts — JSON Schema validation + TypeScript types.

Use this alongside [`@sonate/sdk`](https://www.npmjs.com/package/@sonate/sdk) when you want typed receipt objects or local schema validation in downstream tooling.

## Install

```bash
npm install @sonate/schemas
```

## Usage

### Validate a receipt

```typescript
import { receiptValidator } from '@sonate/schemas';

const result = receiptValidator.validateJSON(receipt);
if (result.valid) {
  console.log('Receipt is valid');
} else {
  console.error('Validation errors:', result.errors);
}
```

### TypeScript types

```typescript
import type {
  TrustReceipt,
  AIInteraction,
  DigitalSignature,
  HashChain,
  CreateReceiptInput,
  VerificationResult,
} from '@sonate/schemas';
```

## What's Included

- **JSON Schema** (`receipt.schema.json`) — V2 Trust Receipt schema with AJV validation
- **TypeScript interfaces** — `TrustReceipt`, `AIInteraction`, `Telemetry`, `PolicyState`, etc.
- **Validator** — Runtime validation using AJV with detailed error reporting

## Receipt Structure (V2)

A Trust Receipt contains:

| Field | Description |
|-------|-------------|
| `id` | SHA-256 hash of canonical content |
| `version` | Schema version (`"2.0.0"` or `"2.2.0"`) |
| `timestamp` | ISO 8601 timestamp |
| `agent_did` | DID of the AI agent |
| `human_did` | DID of the human user |
| `policy_version` | Optional — version of policy that governed the interaction |
| `interaction` | Prompt/response data (raw or hashed) |
| `chain` | Hash chain for immutability (`chain_length` optional) |
| `signature` | Ed25519 cryptographic signature (`public_key`, `timestamp_signed` optional) |

The validators accept both `2.0.0` and `2.2.0` receipts. `2.0.0` receipts carry raw
`interaction.prompt`/`interaction.response` and a required `policy_version`; `2.2.0`
receipts are privacy-preserving by default (hash-only) and treat `policy_version` as
optional. At least one of `prompt`/`prompt_hash` and one of `response`/`response_hash`
must be present.

### Privacy-by-Default

The `interaction` object supports both raw content and content hashing:

```typescript
// Hashes only (privacy-preserving, default)
interaction: {
  prompt_hash: "a1b2c3...",
  response_hash: "d4e5f6...",
  model: "gpt-4"
}

// Raw content (opt-in)
interaction: {
  prompt: "What is quantum computing?",
  response: "Quantum computing uses...",
  prompt_hash: "a1b2c3...",
  response_hash: "d4e5f6...",
  model: "gpt-4"
}
```

### v2.2.0 fields

Beyond the `2.0.0` shape, validators also accept:

- `chain.chain_length` — position of a receipt in its hash chain
- `signature.public_key` / `signature.timestamp_signed`
- `telemetry.ciq_metrics` and `telemetry.custom_scores` — attestation scores
- `metadata` — arbitrary application-defined keys

## Related Packages

- [`@sonate/sdk`](https://www.npmjs.com/package/@sonate/sdk) — primary platform SDK for evaluating interactions and receiving signed receipts
- [`@sonate/trust-receipts`](https://www.npmjs.com/package/@sonate/trust-receipts) — advanced local/self-managed receipt generation
- [`@sonate/verify-sdk`](https://www.npmjs.com/package/@sonate/verify-sdk) — Verify receipts (browser + Node.js)

## License

MIT
