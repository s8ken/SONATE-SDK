"""
Local Trust Receipt verifier (v2.2.0) — Python port of ``@sonate/verify-sdk``.

Runs the same five checks the JavaScript verifier does, entirely offline:

1. structure  — required fields (``id`` and ``signature.value``) present.
2. hash       — recomputed receipt ``id`` matches the supplied ``id``.
3. signature  — Ed25519 signature verifies over the canonical (signature-stripped)
                receipt.
4. chain      — ``chain_hash`` matches ``sha256(canonical(chain_hash='') + previous_hash)``.
5. timestamp  — within the allowed age / future-skew window.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union

from . import contract
from .crypto import canonicalize, sha256_hex, verify_detached

__all__ = ["Check", "VerificationResult", "verify_receipt", "quick_verify"]

DEFAULT_MAX_AGE_MS = 365 * 24 * 60 * 60 * 1000
DEFAULT_MAX_FUTURE_MS = 5 * 60 * 1000


@dataclass
class Check:
    passed: bool = False
    message: str = ""


@dataclass
class VerificationResult:
    valid: bool = False
    checks: Dict[str, Check] = field(default_factory=dict)
    trust_score: Optional[float] = None
    errors: List[str] = field(default_factory=list)
    receipt: Optional[Dict[str, Any]] = None


def _parse_iso(timestamp: str) -> datetime:
    """Parse an ISO 8601 timestamp (accepting a trailing ``Z``) as an aware datetime."""
    normalized = timestamp.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _canonicalize_without_signature(receipt: Dict[str, Any]) -> str:
    payload = contract.clone(receipt)
    payload.pop("signature", None)
    return canonicalize(payload)


def verify_receipt(
    receipt: Dict[str, Any],
    public_key: Union[str, bytes],
    *,
    max_age_ms: int = DEFAULT_MAX_AGE_MS,
    max_future_ms: int = DEFAULT_MAX_FUTURE_MS,
) -> VerificationResult:
    """Verify a v2.2.0 receipt against ``public_key`` and return a detailed result."""
    result = VerificationResult(
        checks={
            "structure": Check(),
            "signature": Check(),
            "hash": Check(),
            "chain": Check(),
            "timestamp": Check(),
        },
        receipt=receipt,
    )

    signature = receipt.get("signature") or {}
    signature_value = signature.get("value")
    receipt_id = receipt.get("id") or receipt.get("self_hash")

    # 1. Structure
    if not receipt_id or not signature_value:
        missing = []
        if not receipt_id:
            missing.append("id")
        if not signature_value:
            missing.append("signature")
        msg = f"Missing required fields: {', '.join(missing)}"
        result.checks["structure"].message = msg
        result.errors.append(msg)
        if receipt.get("self_hash") and not receipt.get("id"):
            v1_msg = 'This receipt uses V1 format (self_hash). V2 format with "id" field is required.'
            result.checks["structure"].message = v1_msg
            result.errors.append(v1_msg)
    else:
        result.checks["structure"].passed = True
        result.checks["structure"].message = "Valid V2 receipt structure"

    # 2. Receipt id hash
    if receipt_id:
        try:
            computed_id = contract.generate_receipt_id(receipt)
        except ValueError:
            # A value JSON can't canonicalize identically in JavaScript (see
            # crypto._js_safe_numbers): no producer could have signed it.
            computed_id = None
        hash_valid = computed_id == receipt_id
        result.checks["hash"].passed = hash_valid
        result.checks["hash"].message = (
            "Receipt hash matches canonical payload"
            if hash_valid
            else "Receipt hash does not match canonical payload"
        )
        if not hash_valid:
            result.errors.append("Receipt hash verification failed")
    else:
        result.checks["hash"].message = "No receipt id provided"
        result.errors.append(result.checks["hash"].message)

    # 3. Signature
    if signature_value and public_key:
        try:
            canonical = _canonicalize_without_signature(receipt)
            is_valid = verify_detached(signature_value, canonical, public_key)
            result.checks["signature"].passed = is_valid
            result.checks["signature"].message = (
                "Ed25519 signature verified"
                if is_valid
                else "Signature verification failed - content may have been tampered"
            )
            if not is_valid:
                result.errors.append("Signature verification failed")
        except (ValueError, TypeError):
            result.checks["signature"].message = "Malformed signature or public-key encoding"
            result.errors.append("Signature verification failed: invalid hex encoding")
    else:
        result.checks["signature"].message = "No signature or public key provided"
        result.errors.append(result.checks["signature"].message)

    # 4. Chain hash
    chain = receipt.get("chain") or {}
    chain_hash = chain.get("chain_hash")
    previous_hash = chain.get("previous_hash")
    if chain_hash and previous_hash and previous_hash != "GENESIS":
        expected = _expected_chain_hash(receipt, previous_hash)
        chain_valid = expected == chain_hash
        result.checks["chain"].passed = chain_valid
        result.checks["chain"].message = (
            "Chain hash verified" if chain_valid else "Chain hash mismatch - receipt may have been tampered"
        )
        if not chain_valid:
            result.errors.append("Chain hash verification failed")
    elif previous_hash == "GENESIS":
        if chain_hash:
            expected = _expected_chain_hash(receipt, "GENESIS")
            chain_valid = expected == chain_hash
            result.checks["chain"].passed = chain_valid
            result.checks["chain"].message = (
                "Genesis chain hash verified" if chain_valid else "Genesis chain hash mismatch"
            )
            if not chain_valid:
                result.errors.append("Genesis chain hash verification failed")
        else:
            result.checks["chain"].passed = True
            result.checks["chain"].message = "First receipt in chain (GENESIS)"
    else:
        result.checks["chain"].passed = True
        result.checks["chain"].message = "Chain verification skipped (no chain data)"

    # 5. Timestamp
    timestamp = receipt.get("timestamp")
    if timestamp:
        try:
            receipt_time = _parse_iso(timestamp)
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(milliseconds=max_age_ms)
            future_limit = now + timedelta(milliseconds=max_future_ms)
            if receipt_time > future_limit:
                result.checks["timestamp"].message = "Timestamp is in the future"
                result.errors.append(result.checks["timestamp"].message)
            elif receipt_time < cutoff:
                days = round(max_age_ms / (24 * 60 * 60 * 1000))
                result.checks["timestamp"].message = f"Timestamp is older than max age ({days} days)"
                result.errors.append(result.checks["timestamp"].message)
            else:
                result.checks["timestamp"].passed = True
                result.checks["timestamp"].message = f"Issued {receipt_time.isoformat()}"
        except ValueError:
            result.checks["timestamp"].message = "Invalid timestamp"
            result.errors.append(result.checks["timestamp"].message)
    else:
        result.checks["timestamp"].message = "No timestamp present"
        result.errors.append(result.checks["timestamp"].message)

    result.trust_score = _trust_score(receipt.get("telemetry") or {})

    result.valid = all(
        result.checks[name].passed
        for name in ("structure", "hash", "signature", "chain", "timestamp")
    )
    return result


def _expected_chain_hash(receipt: Dict[str, Any], previous_hash: str) -> Optional[str]:
    payload = contract.clone(receipt)
    payload.pop("signature", None)
    payload["chain"] = {**(payload.get("chain") or {}), "chain_hash": ""}
    try:
        return sha256_hex(canonicalize(payload) + previous_hash)
    except ValueError:
        # Not canonicalizable (see the hash check): the chain hash can't match.
        return None


def _trust_score(telemetry: Dict[str, Any]) -> Optional[float]:
    if isinstance(telemetry.get("overall_trust_score"), (int, float)):
        return round(telemetry["overall_trust_score"])
    ciq = telemetry.get("ciq_metrics")
    if isinstance(ciq, dict):
        clarity = ciq.get("clarity", 0) or 0
        integrity = ciq.get("integrity", 0) or 0
        quality = ciq.get("quality", 0) or 0
        return round(((clarity + integrity + quality) / 3) * 100)
    if telemetry.get("resonance_score") is not None:
        return round(telemetry["resonance_score"] * 100)
    return None


def quick_verify(receipt: Dict[str, Any], public_key: Union[str, bytes], **kwargs) -> bool:
    """Return only the boolean validity of a receipt."""
    return verify_receipt(receipt, public_key, **kwargs).valid
