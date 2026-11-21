"""
TrustReceipts wrapper (v2.2.0) — the main SDK entry point.

Wrap any model call to automatically produce a signed, hash-chained SONATE
trust receipt::

    receipts = TrustReceipts(private_key=PRIVATE_KEY_HEX)
    response, receipt = receipts.wrap(
        lambda: call_model(messages),
        session_id="user-123",
        agent_did="did:sonate:agent-1",
        human_did="did:sonate:human-1",
        model="gpt-4",
        prompt="Hello",
    )
"""

from collections.abc import Mapping
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .crypto import bytes_to_hex, generate_key_pair, get_public_key, normalize_public_key
from .trust_receipt import TrustReceipt
from .verifier import verify_receipt

__all__ = ["TrustReceipts"]


_MISSING = object()


def _field(obj: Any, name: str) -> Any:
    """Read ``name`` as a mapping key or, for SDK response objects, an attribute."""
    if isinstance(obj, Mapping):
        return obj.get(name, _MISSING)
    if obj is None or isinstance(obj, (str, bytes, int, float, list, tuple)):
        return _MISSING
    return getattr(obj, name, _MISSING)


def _extract_response_content(response: Any) -> Any:
    """Best-effort extraction of text from common AI response shapes.

    Handles both plain dicts and the response objects the OpenAI
    (``choices[0].message.content``) and Anthropic (``content[0].text``) Python
    SDKs return.
    """
    choices = _field(response, "choices")
    if isinstance(choices, (list, tuple)) and choices:
        message = _field(choices[0], "message")
        if message is not _MISSING:
            content = _field(message, "content")
            if content is not _MISSING:
                return content
    content = _field(response, "content")
    if isinstance(content, (list, tuple)) and content:
        text = _field(content[0], "text")
        if text is not _MISSING:
            return text
    return response


class TrustReceipts:
    """SONATE Trust Receipts SDK (v2.2.0)."""

    def __init__(
        self,
        private_key: Optional[Union[str, bytes]] = None,
        public_key: Optional[Union[str, bytes]] = None,
        default_agent_did: Optional[str] = None,
        default_human_did: Optional[str] = None,
        key_version: str = "key_v1",
    ):
        if private_key:
            self.private_key_hex = private_key if isinstance(private_key, str) else bytes_to_hex(private_key)
            self.public_key_hex = (
                (public_key if isinstance(public_key, str) else bytes_to_hex(public_key))
                if public_key
                else get_public_key(self.private_key_hex)
            )
        else:
            self.private_key_hex, self.public_key_hex = generate_key_pair()

        self.default_agent_did = default_agent_did
        self.default_human_did = default_human_did
        self.key_version = key_version

    @staticmethod
    def generate_key_pair() -> Tuple[str, str]:
        """Return a new ``(private_seed_hex, public_key_hex)`` pair."""
        return generate_key_pair()

    def get_public_key(self) -> str:
        return self.public_key_hex

    def create_receipt(
        self,
        *,
        session_id: str,
        prompt: Optional[str] = None,
        response: Optional[str] = None,
        model: str,
        provider: Optional[str] = None,
        agent_did: Optional[str] = None,
        human_did: Optional[str] = None,
        mode: str = "constitutional",
        telemetry: Optional[Dict[str, Any]] = None,
        scores: Optional[Dict[str, float]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        policy_version: Optional[str] = None,
        policy_state: Optional[Dict[str, Any]] = None,
        previous_receipt: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
        include_content: bool = False,
        interaction: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create and sign a single receipt, returning it as a dict."""
        previous_hash, chain_length = self._chain_link(previous_receipt)

        receipt = TrustReceipt(
            session_id=session_id,
            agent_did=agent_did or self.default_agent_did,
            human_did=human_did or self.default_human_did,
            mode=mode,
            interaction=interaction,
            prompt=prompt,
            response=response,
            model=model,
            provider=provider,
            telemetry=telemetry,
            scores=scores,
            metadata=metadata,
            policy_version=policy_version,
            policy_state=policy_state,
            previous_hash=previous_hash,
            chain_length=chain_length,
            timestamp=timestamp,
            key_version=self.key_version,
            include_content=include_content,
        )
        receipt.sign(self.private_key_hex)
        return receipt.to_json()

    def wrap(
        self,
        fn: Callable[[], Any],
        *,
        session_id: str,
        input: Any = None,
        model: str,
        provider: Optional[str] = None,
        agent_did: Optional[str] = None,
        human_did: Optional[str] = None,
        mode: str = "constitutional",
        telemetry: Optional[Dict[str, Any]] = None,
        scores: Optional[Dict[str, float]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        policy_version: Optional[str] = None,
        policy_state: Optional[Dict[str, Any]] = None,
        previous_receipt: Optional[Dict[str, Any]] = None,
        extract_response: Optional[Callable[[Any], Any]] = None,
        include_content: bool = False,
        timestamp: Optional[str] = None,
    ) -> Tuple[Any, Dict[str, Any]]:
        """Execute ``fn()`` and produce a signed receipt for the interaction.

        Returns ``(response, receipt_dict)``. The prompt is hashed from ``input``
        (coerced to a string) and the response from the extracted text content.
        """
        response = fn()
        response_content = extract_response(response) if extract_response else _extract_response_content(response)

        prompt_str = input if isinstance(input, str) else ("" if input is None else _to_text(input))
        response_str = response_content if isinstance(response_content, str) else _to_text(response_content)

        receipt = self.create_receipt(
            session_id=session_id,
            prompt=prompt_str,
            response=response_str,
            model=model,
            provider=provider,
            agent_did=agent_did,
            human_did=human_did,
            mode=mode,
            telemetry=telemetry,
            scores=scores,
            metadata=metadata,
            policy_version=policy_version,
            policy_state=policy_state,
            previous_receipt=previous_receipt,
            timestamp=timestamp,
            include_content=include_content,
        )
        return response, receipt

    def verify_receipt(self, receipt: Dict[str, Any], public_key: Optional[Union[str, bytes]] = None) -> bool:
        """Verify a receipt dict; uses the instance public key by default."""
        key = public_key if public_key is not None else self.public_key_hex
        return verify_receipt(receipt, key).valid

    def verify_chain(
        self, receipts: List[Dict[str, Any]], public_key: Optional[Union[str, bytes]] = None
    ) -> Dict[str, Any]:
        """Verify a chain of receipts: signatures, ids, and chain linkage."""
        key = public_key if public_key is not None else self.public_key_hex
        errors: List[str] = []
        for i, current in enumerate(receipts):
            result = verify_receipt(current, key)
            if not result.valid:
                errors.append(f"Receipt {i}: {'; '.join(result.errors) or 'invalid'}")
            if i > 0:
                prev_hash = (receipts[i - 1].get("chain") or {}).get("chain_hash")
                cur_prev = (current.get("chain") or {}).get("previous_hash")
                if cur_prev != prev_hash:
                    errors.append(f"Receipt {i}: chain broken (previous_hash mismatch)")
        return {"valid": len(errors) == 0, "errors": errors}

    @staticmethod
    def _chain_link(previous_receipt: Optional[Dict[str, Any]]) -> Tuple[str, Optional[int]]:
        """Return the next receipt's ``previous_hash`` and ``chain_length``.

        Matches the TypeScript SDK: the position is the predecessor's plus one,
        or 1 for the first receipt. When the predecessor doesn't record its
        position (``chain_length`` is optional), the position is unknown and is
        omitted rather than invented.
        """
        if not previous_receipt:
            return "GENESIS", 1
        prev_chain = previous_receipt.get("chain") or {}
        previous_hash = prev_chain.get("chain_hash") or "GENESIS"
        prev_length = prev_chain.get("chain_length")
        if isinstance(prev_length, int) and not isinstance(prev_length, bool) and prev_length > 0:
            return previous_hash, prev_length + 1
        return previous_hash, (1 if previous_hash == "GENESIS" else None)


def _to_text(value: Any) -> str:
    """Coerce non-string content to a stable string for hashing."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    from .crypto import canonicalize

    # SDK response objects (OpenAI, Anthropic) are pydantic models: hash their
    # JSON form, as for a plain dict, rather than failing after the model call.
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        value = dump(mode="json")
    return canonicalize(value)
