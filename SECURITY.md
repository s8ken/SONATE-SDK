# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security → Report a vulnerability** on this repository. Don't open a public
issue for a security problem.

Include the affected package and version, what an attacker can do, and steps or
a receipt that reproduces it. You'll get an acknowledgement within 5 working
days.

## In scope

- Accepting a receipt that should fail: a forged or altered receipt that
  verifies, a chain break that isn't detected, or a mismatch between the
  TypeScript and Python implementations.
- Signing or canonicalization bugs that make receipts non-reproducible.
- Private key handling in the SDKs.

## Out of scope

The limits described in [the spec](spec/receipt-format.md#9-what-a-valid-receipt-proves)
are not vulnerabilities: a receipt doesn't prove that a model produced its
output, that its metrics are accurate, or that its timestamp is true.

## Test keys

The fixtures are signed with a fixed, publicly known test seed (32 bytes of
`0x42`). Never use it, or any key committed to this repository, for real
receipts.
