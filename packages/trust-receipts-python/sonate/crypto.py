"""
Cryptographic primitives for SONATE Trust Receipts (v2.2.0).

This module is the Python counterpart of the platform's
``receipt-crypto-contract.ts`` low-level primitives:

- RFC 8785 / JCS canonicalization (via the ``rfc8785`` package, which matches
  ``json-canonicalize`` byte-for-byte, including ECMAScript number formatting).
- SHA-256 hex digests.
- Ed25519 detached signatures over UTF-8 bytes, using 32-byte seed private keys
  and raw 32-byte public keys encoded as hex (tweetnacl / @noble semantics).
"""

import hashlib
import re
from typing import Any, Union

import rfc8785
from nacl import signing
from nacl.exceptions import BadSignatureError

__all__ = [
    "sha256_hex",
    "canonicalize",
    "canonicalize_bytes",
    "canonicalize_and_hash",
    "generate_key_pair",
    "get_public_key",
    "normalize_private_seed",
    "normalize_public_key",
    "sign_detached",
    "verify_detached",
    "hex_to_bytes",
    "bytes_to_hex",
]

_HEX64_RE = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)


def sha256_hex(data: Union[str, bytes]) -> str:
    """Return the hex-encoded SHA-256 digest of ``data``."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonicalize_bytes(obj: Any) -> bytes:
    """Canonicalize ``obj`` to RFC 8785 (JCS) UTF-8 bytes.

    We rely on ``rfc8785`` rather than ``json.dumps(sort_keys=True)`` because the
    latter is not JCS-compliant (it mishandles float/number formatting and
    non-ASCII escaping). ``rfc8785`` reproduces the exact byte stream emitted by
    the JavaScript ``json-canonicalize`` library used by the producer and the
    ``@sonate/verify-sdk`` verifier.

    ``None`` is serialized as JSON ``null`` (matching how the JS side keeps
    ``null`` while stripping ``undefined``). Absent optional fields must simply be
    omitted from ``obj`` by the caller — never set to ``None`` — so that the two
    implementations agree.
    """
    return rfc8785.dumps(obj)


def canonicalize(obj: Any) -> str:
    """Canonicalize ``obj`` to an RFC 8785 (JCS) string."""
    return canonicalize_bytes(obj).decode("utf-8")


def canonicalize_and_hash(obj: Any) -> str:
    """Canonicalize ``obj`` and return the hex SHA-256 of the canonical bytes."""
    return sha256_hex(canonicalize_bytes(obj))


def _seed_from(value: Union[str, bytes]) -> bytes:
    """Coerce a private key input into a raw 32-byte Ed25519 seed."""
    if isinstance(value, (bytes, bytearray)):
        seed = bytes(value)
    elif isinstance(value, str):
        stripped = value.strip()
        if _HEX64_RE.match(stripped):
            seed = bytes.fromhex(stripped)
        else:
            # Fall back to hex decoding for any even-length hex, else utf-8 bytes.
            try:
                seed = bytes.fromhex(stripped)
            except ValueError:
                seed = stripped.encode("utf-8")
    else:
        raise TypeError(f"Unsupported private key type: {type(value)!r}")

    if len(seed) != 32:
        raise ValueError(
            f"Expected 32-byte Ed25519 private key seed, received {len(seed)} bytes"
        )
    return seed


def normalize_private_seed(value: Union[str, bytes]) -> bytes:
    """Public wrapper returning the raw 32-byte seed for a private key input."""
    return _seed_from(value)


def normalize_public_key(value: Union[str, bytes]) -> bytes:
    """Coerce a public key input into raw 32 bytes."""
    if isinstance(value, (bytes, bytearray)):
        pub = bytes(value)
    elif isinstance(value, str):
        stripped = value.strip()
        try:
            pub = bytes.fromhex(stripped)
        except ValueError:
            pub = stripped.encode("utf-8")
    else:
        raise TypeError(f"Unsupported public key type: {type(value)!r}")

    if len(pub) != 32:
        raise ValueError(
            f"Expected 32-byte Ed25519 public key, received {len(pub)} bytes"
        )
    return pub


def generate_key_pair() -> "tuple[str, str]":
    """Generate a new Ed25519 key pair as ``(private_seed_hex, public_key_hex)``."""
    key = signing.SigningKey.generate()
    private_hex = bytes(key).hex()
    public_hex = bytes(key.verify_key).hex()
    return private_hex, public_hex


def get_public_key(private_key: Union[str, bytes]) -> str:
    """Derive the hex-encoded public key from a private seed."""
    seed = _seed_from(private_key)
    key = signing.SigningKey(seed)
    return bytes(key.verify_key).hex()


def sign_detached(message: Union[str, bytes], private_key: Union[str, bytes]) -> str:
    """Produce a hex-encoded Ed25519 detached signature over ``message``.

    Mirrors ``nacl.sign.detached`` / ``@noble/ed25519.sign``: the signature is
    computed over the raw UTF-8 bytes of ``message`` using the 32-byte seed.
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
    seed = _seed_from(private_key)
    key = signing.SigningKey(seed)
    return key.sign(message).signature.hex()


def verify_detached(
    signature: Union[str, bytes],
    message: Union[str, bytes],
    public_key: Union[str, bytes],
) -> bool:
    """Verify a hex Ed25519 detached signature; return ``False`` on any failure."""
    try:
        if isinstance(signature, str):
            signature = bytes.fromhex(signature)
        else:
            signature = bytes(signature)
        if isinstance(message, str):
            message = message.encode("utf-8")
        pub = normalize_public_key(public_key)
        signing.VerifyKey(pub).verify(message, signature)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def hex_to_bytes(hex_string: str) -> bytes:
    """Convert a hex string to bytes."""
    return bytes.fromhex(hex_string)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to a hex string."""
    return data.hex()
