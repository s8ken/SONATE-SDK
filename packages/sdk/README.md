# @sonate/sdk

[![npm version](https://img.shields.io/npm/v/@sonate/sdk.svg)](https://www.npmjs.com/package/@sonate/sdk)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Official platform SDK for sending AI interactions to SONATE and receiving signed governance receipts.**

This is the primary integration path for SONATE as a service.

Use `@sonate/sdk` when you want to:
- send a `prompt + response` pair to SONATE
- receive constitutional scores, kernel verdicts, and a signed receipt
- get a public verification URL back immediately
- wrap existing OpenAI / Anthropic / custom model calls with one client

## Install

```bash
npm install @sonate/sdk
```

## Quick Start

```ts
import { SonateClient } from '@sonate/sdk';

const sonate = new SonateClient({
  apiKey: process.env.SONATE_API_KEY!,
});

const evaluation = await sonate.evaluate({
  sessionId: 'session-123',
  model: 'gpt-4o-mini',
  prompt: 'Should we hire candidates based on culture fit?',
  response: 'Use structured, job-relevant criteria and avoid vague personality proxies.',
});

console.log(evaluation.status);
console.log(evaluation.trustScore.overall);
console.log(evaluation.receiptHash);
console.log(evaluation.verificationUrl);
```

Full examples:
- [`examples/evaluate.ts`](./examples/evaluate.ts) — submit an existing prompt/response pair to SONATE
- [`examples/wrap-openai.ts`](./examples/wrap-openai.ts) — wrap an OpenAI call and attach a SONATE receipt

## Wrap Existing Model Calls

```ts
import OpenAI from 'openai';
import { SonateClient } from '@sonate/sdk';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const sonate = new SonateClient({ apiKey: process.env.SONATE_API_KEY! });

const { result, evaluation } = await sonate.wrap(
  () =>
    openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'Explain zero-knowledge proofs.' }],
    }),
  {
    sessionId: 'session-123',
    prompt: 'Explain zero-knowledge proofs.',
    model: 'gpt-4o-mini',
    provider: 'openai',
  }
);

console.log(result.choices[0].message.content);
console.log(evaluation.kernelSummary);
console.log(evaluation.verificationUrl);
```

If your provider returns a different shape, pass `extractResponse`:

```ts
const wrapped = await sonate.wrap(callMyModel, {
  prompt: userPrompt,
  extractResponse: (result) => result.output.text,
});
```

## API

### `new SonateClient(options)`

```ts
const client = new SonateClient({
  apiKey: 'sk_live_...',
  baseUrl: 'https://yseeku-backend.fly.dev',
  tenantId: 'tenant_123',
});
```

### `client.evaluate(input)`

Sends an already-generated interaction to SONATE for governance evaluation and receipt minting.

### `client.wrap(operation, options)`

Runs your model call, extracts the response text, then sends the interaction to SONATE.

### `client.getReceipt(receiptHash)`

Fetches the signed receipt payload from the SONATE platform.

### `client.verifyReceipt(receiptHash)`

Calls the public proof endpoint for a receipt hash.

### `client.verifyReceiptOffline(receipt, publicKey?)`

Uses `@sonate/verify-sdk` under the hood to perform local verification in Node or the browser.

## Positioning

`@sonate/sdk` is the **platform SDK**.

It talks to SONATE's hosted governance infrastructure:
- constitutional scoring
- semantic judging
- kernel enforcement
- receipt signing
- receipt ledgering
- public verification

If you want local receipt generation or advanced self-managed signing primitives, use `@sonate/trust-receipts`.

## Related Packages

- [`@sonate/verify-sdk`](https://www.npmjs.com/package/@sonate/verify-sdk) — local cryptographic verification
- [`@sonate/schemas`](https://www.npmjs.com/package/@sonate/schemas) — shared receipt types and schema validation
- [`@sonate/trust-receipts`](https://www.npmjs.com/package/@sonate/trust-receipts) — advanced local/self-managed receipt tooling

## Examples

Repo examples:

```bash
node --env-file=.env ./packages/sdk/examples/evaluate.ts
node --env-file=.env ./packages/sdk/examples/wrap-openai.ts
```

Run them from the `SONATE-SDK` repository root after setting `SONATE_API_KEY`.
`wrap-openai.ts` also requires `OPENAI_API_KEY`.

## License

MIT
