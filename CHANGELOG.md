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
