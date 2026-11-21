"""
SONATE Trust Receipts Python SDK (v2.2.0 receipts)
==================================================

Generate and verify SONATE v2.2.0 trust receipts that are byte-for-byte
compatible with the platform's JavaScript implementation and ``@sonate/verify-sdk``.

Quick start::

    from sonate import TrustReceipts

    receipts = TrustReceipts(private_key=PRIVATE_KEY_HEX)
    response, receipt = receipts.wrap(
        lambda: call_model(messages),
        session_id="user-123",
        agent_did="did:sonate:agent-1",
        human_did="did:sonate:human-1",
        model="gpt-4",
        prompt="Explain quantum computing.",
    )
    assert receipts.verify_receipt(receipt)

Low-level::

    from sonate import TrustReceipt, verify_receipt

    r = TrustReceipt(session_id="s1", agent_did="did:sonate:a",
                     human_did="did:sonate:h", model="gpt-4",
                     prompt="hi", response="hello")
    r.sign(PRIVATE_KEY_HEX)
    result = verify_receipt(r.to_json(), PUBLIC_KEY_HEX)
"""

__version__ = "3.0.0"
__author__ = "SONATE"
__license__ = "MIT"

from .trust_receipt import TrustReceipt, iso_now
from .wrapper import TrustReceipts
from .verifier import verify_receipt, quick_verify, VerificationResult, Check
from . import contract
from .crypto import (
    generate_key_pair,
    get_public_key,
    sha256_hex,
    canonicalize,
    canonicalize_and_hash,
    sign_detached,
    verify_detached,
    hex_to_bytes,
    bytes_to_hex,
)
from .client import (
    SonateClient,
    DetectionResult,
    TruthDebtResult,
    PolicyResult,
    PipelineResult,
    SonateAPIError,
    SonateConnectionError,
)

__all__ = [
    # Receipts
    "TrustReceipt",
    "TrustReceipts",
    "iso_now",
    # Verification
    "verify_receipt",
    "quick_verify",
    "VerificationResult",
    "Check",
    # Crypto / contract
    "contract",
    "generate_key_pair",
    "get_public_key",
    "sha256_hex",
    "canonicalize",
    "canonicalize_and_hash",
    "sign_detached",
    "verify_detached",
    "hex_to_bytes",
    "bytes_to_hex",
    # REST client
    "SonateClient",
    "DetectionResult",
    "TruthDebtResult",
    "PolicyResult",
    "PipelineResult",
    "SonateAPIError",
    "SonateConnectionError",
]
