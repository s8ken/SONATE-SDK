"""
Receipt crypto contract (v2.2.0) — Python port of ``receipt-crypto-contract.ts``.

These functions define how a SONATE Trust Receipt is turned into the exact byte
streams that get hashed and signed. They are the single source of truth that the
``TrustReceipt`` class and the verifier both route through, guaranteeing the
producer and verifier agree byte-for-byte with the JavaScript implementation.

Field-presence rules (matching the JS ``stripUndefined`` semantics):
- Absent optional fields must be omitted from the receipt dict entirely. The
  builders here never introduce ``None`` values, so canonicalization never emits
  spurious ``null``s. Explicit ``null`` inside user-supplied ``metadata`` is
  preserved (the JS side keeps ``null`` too).
"""

import copy
from typing import Any, Dict

from .crypto import canonicalize, sha256_hex

__all__ = [
    "clone",
    "build_receipt_base_for_id",
    "build_receipt_for_signature",
    "build_receipt_for_chain",
    "canonicalize_for_id",
    "canonicalize_for_signature",
    "canonicalize_for_chain",
    "generate_receipt_id",
    "generate_chain_hash",
]

Receipt = Dict[str, Any]


def clone(receipt: Receipt) -> Receipt:
    """Deep-copy a receipt dict (equivalent to ``JSON.parse(JSON.stringify(...))``)."""
    return copy.deepcopy(receipt)


def build_receipt_base_for_id(receipt: Receipt) -> Receipt:
    """Build the payload whose SHA-256 becomes the receipt ``id``.

    Removes ``signature`` and ``id`` and forces ``chain.chain_hash`` to an empty
    string, keeping ``previous_hash`` and ``chain_length``.
    """
    base = clone(receipt)
    base.pop("signature", None)
    base.pop("id", None)
    if base.get("chain") is not None:
        base["chain"] = {**base["chain"], "chain_hash": ""}
    return base


def build_receipt_for_signature(receipt: Receipt) -> Receipt:
    """Build the payload that gets Ed25519-signed (only ``signature`` removed).

    ``id`` and the real ``chain.chain_hash`` remain present.
    """
    payload = clone(receipt)
    payload.pop("signature", None)
    return payload


def build_receipt_for_chain(receipt: Receipt) -> Receipt:
    """Build the payload used for the chain hash: signature removed, chain_hash=''.

    ``id`` remains present (only ``signature`` and ``chain.chain_hash`` differ from
    the signing payload).
    """
    payload = build_receipt_for_signature(receipt)
    if payload.get("chain") is not None:
        payload["chain"] = {**payload["chain"], "chain_hash": ""}
    return payload


def canonicalize_for_id(receipt: Receipt) -> str:
    return canonicalize(build_receipt_base_for_id(receipt))


def canonicalize_for_signature(receipt: Receipt) -> str:
    return canonicalize(build_receipt_for_signature(receipt))


def canonicalize_for_chain(receipt: Receipt) -> str:
    return canonicalize(build_receipt_for_chain(receipt))


def generate_receipt_id(receipt: Receipt) -> str:
    """Compute the receipt ``id`` = SHA-256 hex of the id-base canonical payload."""
    return sha256_hex(canonicalize_for_id(receipt))


def generate_chain_hash(receipt: Receipt) -> str:
    """Compute ``chain.chain_hash`` = SHA-256 hex of ``canonical + previous_hash``.

    ``previous_hash`` defaults to ``'GENESIS'`` when absent/empty, matching the JS
    ``chain?.previous_hash || 'GENESIS'`` behavior.
    """
    chain_ready = build_receipt_for_chain(receipt)
    canonical = canonicalize(chain_ready)
    chain = chain_ready.get("chain") or {}
    previous_hash = chain.get("previous_hash") or "GENESIS"
    return sha256_hex(canonical + previous_hash)
