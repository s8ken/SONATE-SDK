"""
TrustReceipt (v2.2.0) — cryptographically signed AI interaction records.

This is a byte-for-byte compatible Python implementation of the SONATE v2.2.0
receipt contract. Receipts generated here verify with ``@sonate/verify-sdk`` and
the backend producer, and vice versa.

Friendly API::

    receipt = TrustReceipt(
        session_id="session-1",
        agent_did="did:sonate:agent-1",
        human_did="did:sonate:human-1",
        mode="constitutional",
        prompt="What is the capital of France?",
        response="Paris.",
        model="gpt-4",
        provider="openai",
        timestamp="2026-01-01T00:00:00.000Z",
    )
    receipt.sign(private_key_hex)
    assert receipt.verify(public_key_hex)
    data = receipt.to_json()
    restored = TrustReceipt.from_json(data)   # re-checks id integrity
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

from . import contract
from .crypto import (
    canonicalize,
    get_public_key,
    sha256_hex,
    sign_detached,
    verify_detached,
)

__all__ = ["TrustReceipt", "iso_now"]

VERSION = "2.2.0"
DID_PREFIX = "did:sonate:"

# The `scores=` convenience alias partitions its keys the same way the JS SDK does
# so the ergonomic path is cross-language-identical: clarity/integrity/quality land
# in telemetry.ciq_metrics; every other key lands in telemetry.custom_scores.
CIQ_SCORE_KEYS = ("clarity", "integrity", "quality")


def _merge_scores_into_telemetry(telemetry, scores):
    """Apply the ``scores`` alias on top of an optional explicit ``telemetry``.

    Rules (mirroring the JS SDK exactly):
      1. Base is the explicit telemetry if given, else empty.
      2. Partition scores: {clarity, integrity, quality} -> ciq_metrics; the rest
         -> custom_scores.
      3/4. Merge each non-empty bucket over any existing sub-object; scores win on
         key collisions within their bucket.
      5. If the result is empty, return None so telemetry is omitted entirely.
    """
    result = dict(telemetry) if telemetry else {}
    if scores:
        ciq = {k: v for k, v in scores.items() if k in CIQ_SCORE_KEYS}
        custom = {k: v for k, v in scores.items() if k not in CIQ_SCORE_KEYS}
        if ciq:
            result["ciq_metrics"] = {**result.get("ciq_metrics", {}), **ciq}
        if custom:
            result["custom_scores"] = {**result.get("custom_scores", {}), **custom}
    return result or None


def iso_now() -> str:
    """Return the current UTC time as a JS-``toISOString``-style timestamp.

    e.g. ``2026-07-23T12:34:56.789Z`` (millisecond precision, ``Z`` suffix).
    """
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _as_did(value: Optional[str]) -> Optional[str]:
    """Prefix a bare identifier with ``did:sonate:`` unless it already is a DID."""
    if value is None:
        return None
    if value.startswith("did:"):
        return value
    return DID_PREFIX + value


class TrustReceipt:
    """A SONATE v2.2.0 trust receipt with a developer-friendly constructor."""

    def __init__(
        self,
        *,
        session_id: str,
        agent_did: Optional[str] = None,
        human_did: Optional[str] = None,
        agent_id: Optional[str] = None,
        human_id: Optional[str] = None,
        mode: str = "constitutional",
        interaction: Optional[Dict[str, Any]] = None,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        prompt_hash: Optional[str] = None,
        response_hash: Optional[str] = None,
        telemetry: Optional[Dict[str, Any]] = None,
        scores: Optional[Dict[str, float]] = None,
        policy_state: Optional[Dict[str, Any]] = None,
        policy_version: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        previous_hash: Optional[str] = None,
        prev_receipt_hash: Optional[str] = None,
        chain_length: Optional[int] = None,
        timestamp: Optional[str] = None,
        key_version: str = "key_v1",
        include_content: bool = False,
        timestamp_signed: Optional[str] = None,
        public_key: Optional[str] = None,
    ):
        if mode not in ("constitutional", "directive"):
            raise ValueError(f"mode must be 'constitutional' or 'directive', got {mode!r}")

        self.session_id = session_id
        self.agent_did = agent_did or _as_did(agent_id)
        self.human_did = human_did or _as_did(human_id)
        if not self.agent_did:
            raise ValueError("agent_did (or agent_id) is required")
        if not self.human_did:
            raise ValueError("human_did (or human_id) is required")

        self.mode = mode
        self.timestamp = timestamp or iso_now()
        self.policy_version = policy_version
        self.key_version = key_version
        self.include_content = include_content
        self.metadata = metadata
        self.policy_state = policy_state
        self._timestamp_signed = timestamp_signed
        self._public_key = public_key

        # scores is a friendly alias that merges into telemetry (see mapping above).
        self.telemetry = _merge_scores_into_telemetry(telemetry, scores)

        self.interaction = self._build_interaction(
            interaction, prompt, response, model, provider, prompt_hash, response_hash
        )

        # Chain: first receipt uses GENESIS.
        prev = previous_hash or prev_receipt_hash or "GENESIS"
        self._chain = {"previous_hash": prev, "chain_hash": ""}
        if chain_length is not None:
            self._chain["chain_length"] = chain_length

        self.id: Optional[str] = None
        self.chain_hash: str = ""
        self.signature: Optional[Dict[str, Any]] = None

    # ── construction helpers ────────────────────────────────────────────

    def _build_interaction(
        self,
        interaction: Optional[Dict[str, Any]],
        prompt: Optional[str],
        response: Optional[str],
        model: Optional[str],
        provider: Optional[str],
        prompt_hash: Optional[str],
        response_hash: Optional[str],
    ) -> Dict[str, Any]:
        base: Dict[str, Any] = dict(interaction) if interaction else {}
        if model is not None:
            base["model"] = model
        if provider is not None:
            base["provider"] = provider
        if "model" not in base:
            raise ValueError("interaction.model (or model=) is required")

        prompt_src = base.get("prompt") if base.get("prompt") is not None else prompt
        response_src = base.get("response") if base.get("response") is not None else response

        resolved_prompt_hash = (
            prompt_hash
            if prompt_hash is not None
            else base.get("prompt_hash")
            if base.get("prompt_hash") is not None
            else sha256_hex(prompt_src if prompt_src else "")
        )
        resolved_response_hash = (
            response_hash
            if response_hash is not None
            else base.get("response_hash")
            if base.get("response_hash") is not None
            else sha256_hex(response_src if response_src else "")
        )

        # Privacy-by-default: drop raw content unless include_content is set.
        if not self.include_content:
            base.pop("prompt", None)
            base.pop("response", None)
        else:
            if prompt_src is not None:
                base["prompt"] = prompt_src
            if response_src is not None:
                base["response"] = response_src

        base["prompt_hash"] = resolved_prompt_hash
        base["response_hash"] = resolved_response_hash
        return base

    def _core(self) -> Dict[str, Any]:
        """Receipt payload without ``id``/``signature`` and with ``chain_hash=''``.

        Omits every optional field that is absent so canonicalization matches the
        JS ``stripUndefined`` behavior exactly.
        """
        core: Dict[str, Any] = {
            "version": VERSION,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "agent_did": self.agent_did,
            "human_did": self.human_did,
            "mode": self.mode,
            "interaction": self.interaction,
            "chain": dict(self._chain),
        }
        if self.policy_version is not None:
            core["policy_version"] = self.policy_version
        if self.telemetry is not None:
            core["telemetry"] = self.telemetry
        if self.policy_state is not None:
            core["policy_state"] = self.policy_state
        if self.metadata is not None:
            core["metadata"] = self.metadata
        return core

    # ── signing / verification ──────────────────────────────────────────

    def sign(self, private_key: Union[str, bytes]) -> "TrustReceipt":
        """Compute ``id``, ``chain_hash`` and the Ed25519 signature, in contract order."""
        core = self._core()

        self.id = contract.generate_receipt_id(core)
        with_id = {**core, "id": self.id}

        self.chain_hash = contract.generate_chain_hash(with_id)
        with_chain = {**with_id, "chain": {**core["chain"], "chain_hash": self.chain_hash}}
        self._chain["chain_hash"] = self.chain_hash

        canonical = contract.canonicalize_for_signature(with_chain)
        value = sign_detached(canonical, private_key)

        signature: Dict[str, Any] = {
            "algorithm": "Ed25519",
            "value": value,
            "key_version": self.key_version,
        }
        signature["timestamp_signed"] = self._timestamp_signed or self.timestamp
        if self._public_key is not None:
            signature["public_key"] = self._public_key
        self.signature = signature
        return self

    @property
    def is_signed(self) -> bool:
        return self.signature is not None and bool(self.signature.get("value"))

    def verify(self, public_key: Union[str, bytes]) -> bool:
        """Full local verification against ``public_key``; returns ``True`` if valid.

        Runs the same five checks as ``@sonate/verify-sdk`` (structure, id hash,
        signature, chain, timestamp). Use :func:`sonate.verifier.verify_receipt`
        for the detailed per-check result.
        """
        from .verifier import verify_receipt

        return verify_receipt(self.to_json(), public_key).valid

    # ── serialization ───────────────────────────────────────────────────

    def to_json(self) -> Dict[str, Any]:
        """Return the receipt as a plain dict (signed if :meth:`sign` was called)."""
        if not self.is_signed or self.id is None:
            raise ValueError("Receipt is not signed yet; call sign() before to_json()")
        receipt = self._core()
        receipt["id"] = self.id
        receipt["chain"] = {**self._chain, "chain_hash": self.chain_hash}
        receipt["signature"] = dict(self.signature)
        return receipt

    @staticmethod
    def from_json(data: Dict[str, Any]) -> "TrustReceipt":
        """Reconstruct a :class:`TrustReceipt` from a dict, re-checking id integrity.

        Raises ``ValueError`` if the supplied ``id`` does not match the recomputed
        canonical hash of the payload.
        """
        if not isinstance(data, dict):
            raise TypeError("from_json expects a dict")

        computed_id = contract.generate_receipt_id(data)
        supplied_id = data.get("id")
        if supplied_id is not None and supplied_id != computed_id:
            raise ValueError("Invalid receipt: id does not match canonical payload")

        interaction = dict(data.get("interaction") or {})
        chain = dict(data.get("chain") or {})

        obj = TrustReceipt(
            session_id=data["session_id"],
            agent_did=data["agent_did"],
            human_did=data["human_did"],
            mode=data.get("mode", "constitutional"),
            interaction=interaction,
            telemetry=data.get("telemetry"),
            policy_state=data.get("policy_state"),
            policy_version=data.get("policy_version"),
            metadata=data.get("metadata"),
            previous_hash=chain.get("previous_hash", "GENESIS"),
            chain_length=chain.get("chain_length"),
            timestamp=data["timestamp"],
            include_content=("prompt" in interaction or "response" in interaction),
        )
        # Preserve interaction exactly as supplied (avoid recomputing hashes).
        obj.interaction = interaction
        obj.id = data.get("id") or computed_id
        obj.chain_hash = chain.get("chain_hash", "")
        obj._chain = chain
        obj.signature = data.get("signature")
        if obj.signature and obj.signature.get("key_version"):
            obj.key_version = obj.signature["key_version"]
        return obj

    def __repr__(self) -> str:  # pragma: no cover - convenience only
        return (
            f"TrustReceipt(id={self.id!r}, session_id={self.session_id!r}, "
            f"signed={self.is_signed})"
        )
