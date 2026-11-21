# SONATE Receipts

Verifiable receipts for AI decisions.

Sign a receipt for every model call or agent action. Anyone with your public key
can later check, offline and without trusting you or any service, that the
record hasn't been changed since you signed it and, given the receipts around
it, that none were removed or reordered.

```
VALID    receipt 1
         ✓ structure  ✓ signature  ✓ hash  ✓ chain  ✓ timestamp
INVALID  receipt 2, response hash edited after signing
         ✓ structure  ✗ signature  ✗ hash  ✗ chain  ✓ timestamp
```

## Why

AI agents now approve refunds, triage claims and act on people's behalf. When
something goes wrong, or an auditor or customer asks why it happened, a log file
the operator controls isn't evidence: it can be edited after the fact.

A receipt is evidence. Each one is:

- **Signed** with Ed25519, so it is attributable to one key holder.
- **Content-addressed**: its `id` is the SHA-256 of its canonical JSON
  ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)), so any edit changes it.
- **Hash-chained** to the previous receipt, so deleting or reordering history is
  detectable.
- **Private by default**: it stores SHA-256 hashes of the prompt and response,
  not the text.
- **Independently verifiable**: the verifier is a separate package with two
  small dependencies, in Node.js or the browser.

## What's here

| Package | Language | Install | Use it to |
| --- | --- | --- | --- |
| [`@sonate/trust-receipts`](packages/trust-receipts) | TypeScript | `npm i @sonate/trust-receipts` | Sign and chain receipts; wrap OpenAI or Anthropic calls |
| [`@sonate/verify-sdk`](packages/verify-sdk) | TypeScript | `npm i @sonate/verify-sdk` | Verify receipts and chains, offline |
| [`sonate-trust-receipts`](packages/trust-receipts-python) | Python | `pip install sonate-trust-receipts` | Sign and verify receipts in Python |
| [`@sonate/schemas`](packages/schemas) | TypeScript | `npm i @sonate/schemas` | JSON Schema and types for the receipt format |
| [`@sonate/sdk`](packages/sdk) | TypeScript | `npm i @sonate/sdk` | Client for the hosted SONATE platform ([below](#hosted-platform)) |

The format is specified in [`spec/receipt-format.md`](spec/receipt-format.md).

## Try it

```bash
git clone https://github.com/s8ken/sonate-receipts && cd sonate-receipts
npm install && npm run build
npm run example
```

[`examples/sign-and-verify.mjs`](examples/sign-and-verify.mjs) signs two chained
receipts, verifies them with the separate verifier, then shows that an edit
after signing, or the wrong public key, is rejected. No API keys or network.

## Use it

**Sign** (TypeScript):

```ts
import { TrustReceipts } from '@sonate/trust-receipts';

const receipts = new TrustReceipts({ privateKey: process.env.SONATE_PRIVATE_KEY });

const receipt = await receipts.createReceipt({
  sessionId: 'session-42',
  prompt: 'Customer asks for a $40 refund on order #1042.',
  response: 'Approved: under the $50 auto-approve limit.',
  model: 'gpt-4o-mini',
  previousReceipt, // optional: chains this receipt to the last one
});
```

Or wrap a model call and get the response and its receipt together:

```ts
const { response, receipt } = await receipts.wrap(
  () => openai.chat.completions.create({ model: 'gpt-4o-mini', messages }),
  { sessionId: 'session-42', input: messages, provider: 'openai' }
);
```

**Verify** (anywhere, with only the public key):

```ts
import { verify } from '@sonate/verify-sdk';

const result = await verify(receipt, publicKeyHex);
result.valid;   // true only if structure, hash, signature, chain and timestamp all pass
result.checks;  // each check with a message
```

**Python**:

```python
from sonate import TrustReceipts

receipts = TrustReceipts(
    private_key=seed_hex,
    default_agent_did="did:sonate:refund-agent",
    default_human_did="did:sonate:customer-7",
)
response, receipt = receipts.wrap(
    lambda: call_your_model(prompt),
    session_id="session-42",
    input=prompt,
    model="gpt-4o-mini",
)
assert receipts.verify_receipt(receipt)
```

## How it works

```
receipt fields ──► id         = sha256(canonical(receipt − signature − id, chain_hash = ""))
               ──► chain_hash = sha256(canonical(receipt − signature, chain_hash = "") + previous_hash)
               ──► signature  = Ed25519(canonical(receipt − signature))
```

The signature covers the `id` and the final `chain_hash`. The verifier repeats
each step and compares. See [the spec](spec/receipt-format.md) for the exact
rules, the five verification checks, and the limits of what a receipt proves.

## Guarantees and limits

A valid receipt proves the key holder signed exactly this record (these input
and output hashes, model, session, metrics and chain position) and that nothing
covered by the signature has changed since.

It doesn't prove the model really produced that output, that the metrics are
right, or that the timestamp is true. The producer asserts the timestamp, and a
key holder could re-sign an alternative history. Optional OpenTimestamps
anchoring in `@sonate/trust-receipts`, or sharing receipt hashes with a
counterparty as they're created, narrows that gap.

## Conformance

Golden fixtures are generated from a fixed test seed, and the suites check them
across languages:

- the Python SDK verifies the JavaScript receipts and reproduces them byte for
  byte, and
- `@sonate/verify-sdk` verifies the Python receipts and rejects tampered ones.

Run everything with `npm test` (TypeScript) and `pytest` in
`packages/trust-receipts-python`. CI runs both.

## Hosted platform

`@sonate/sdk` is the client for the hosted SONATE platform, which evaluates
interactions against governance policies and returns platform-signed receipts.
The platform's policy engine is not part of this repository. Its receipts use
the same format, so `@sonate/verify-sdk` verifies them with the platform's
published key:

```ts
import { fetchPublicKey, verify } from '@sonate/verify-sdk';

const result = await verify(receipt, await fetchPublicKey());
```

## Status

The receipt format is at v2.2.0. Published versions: `@sonate/trust-receipts`
3.0.0, `@sonate/verify-sdk` 2.1.1, `@sonate/schemas` 2.2.0,
`sonate-trust-receipts` 3.0.0 on PyPI. [`CHANGELOG.md`](CHANGELOG.md) lists
changes not yet released.

## Security

Report vulnerabilities privately; see [`SECURITY.md`](SECURITY.md).

## License

[MIT](LICENSE)
