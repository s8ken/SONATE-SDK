# Changelog

## Unreleased

### Repository

- Renamed from SONATE-SDK to sonate-receipts and relicensed under MIT. The
  previous `LICENSE` file said "Proprietary Source-Available", contradicting the
  MIT licence declared in every package; MIT now applies throughout.
- Added the Python SDK (`sonate-trust-receipts`, previously developed in the
  SONATE platform repository) as `packages/trust-receipts-python`.
- Added a receipt format specification (`spec/receipt-format.md`), a runnable
  offline example (`examples/sign-and-verify.mjs`), CI for the TypeScript and
  Python packages, and `SECURITY.md`.
- Cross-language conformance now runs in one repository: Python verifies the
  JavaScript fixtures and reproduces them byte for byte, and `@sonate/verify-sdk`
  verifies the Python fixtures.

### `@sonate/verify-sdk`

- `fetchPublicKey()` now defaults to the standard discovery document,
  `https://yseeku-backend.fly.dev/.well-known/sonate-pubkey.json`, instead of a
  demo endpoint. It accepts that document's shape (`sonate.keyFormat.hex`) as
  well as the older flat `{ publicKey }` and `{ data: { publicKey } }` shapes,
  and throws if the response holds no recognizable key.
- Pins `json-canonicalize` to exactly `2.0.0` (was `^1.2.0`), the same version
  the signer uses, so producer and verifier canonicalize identically.

### `@sonate/trust-receipts`

- Pins `json-canonicalize` to exactly `2.0.0` (was `^2.0.0`).

### `sonate-trust-receipts` (Python)

- `wrap()` now reads OpenAI and Anthropic SDK response objects, not only dicts.
  Previously it raised after the model call returned. Other SDK model objects
  are hashed as their JSON form.
- A signed receipt no longer changes when the caller later edits the
  `metadata`, `policy_state`, `telemetry` or `interaction` dict it was built
  from, or the dict `to_json()` returned. Before, such an edit made the receipt
  fail verification.
- `TrustReceipt.from_json()` keeps an empty `telemetry` object, so loaded
  receipts that contain one still verify.
- When the previous receipt doesn't record its `chain_length`, the next receipt
  omits it, as the TypeScript SDK does, instead of claiming position 1.
- Integers beyond ±(2^53 − 1) that JavaScript can represent, such as nanosecond
  timestamps, now canonicalize as JavaScript writes them, so receipts signed in
  JavaScript with such values verify in Python. Integers JavaScript would round
  are still rejected. A receipt containing one now fails verification instead
  of raising.
- `verify_detached()` rejects a non-string signature instead of passing it to
  `bytes()`, which could allocate a buffer of attacker-chosen size.
