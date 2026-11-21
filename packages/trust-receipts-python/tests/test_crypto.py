"""
Tests for sonate.crypto — JCS canonicalization, SHA-256, and Ed25519.

These lock in the low-level behaviours that must match the JavaScript
implementation (json-canonicalize + tweetnacl / @noble) byte-for-byte.
"""

import pytest

from sonate import crypto


# ── JCS canonicalization ────────────────────────────────────────────────

def test_canonicalize_sorts_keys():
    assert crypto.canonicalize({"b": 2, "a": 1, "c": 3}) == '{"a":1,"b":2,"c":3}'


def test_canonicalize_nested_sorted():
    out = crypto.canonicalize({"metadata": {"nested": {"deeply": True}}, "scores": {"clarity": 0.95}})
    assert out == '{"metadata":{"nested":{"deeply":true}},"scores":{"clarity":0.95}}'


def test_canonicalize_number_formatting_matches_ecmascript():
    # RFC 8785 mandates ECMAScript Number.toString formatting.
    got = crypto.canonicalize({"a": 0.95, "b": 0.1, "c": 100, "d": 1e21, "e": 0.000001, "f": 1e-7, "g": -0.0})
    assert got == '{"a":0.95,"b":0.1,"c":100,"d":1e+21,"e":0.000001,"f":1e-7,"g":0}'


def test_canonicalize_unicode_preserved():
    out = crypto.canonicalize({"z": "Hello 世界 \U0001f30d", "y": ""})
    assert out == '{"y":"","z":"Hello 世界 🌍"}'


def test_canonicalize_none_is_null():
    # None maps to JSON null (matching JS keeping explicit null).
    assert crypto.canonicalize({"a": None}) == '{"a":null}'


# ── SHA-256 ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "value,expected",
    [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ],
)
def test_sha256_known_vectors(value, expected):
    assert crypto.sha256_hex(value) == expected


def test_sha256_matches_for_bytes_and_str():
    assert crypto.sha256_hex("abc") == crypto.sha256_hex(b"abc")


# ── Ed25519 ─────────────────────────────────────────────────────────────

SEED = "42" * 32
# Public key derived from a 32-byte 0x42 seed (verified against tweetnacl/@noble).
EXPECTED_PUB = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"


def test_public_key_derivation_deterministic():
    assert crypto.get_public_key(SEED) == EXPECTED_PUB


def test_sign_is_deterministic():
    a = crypto.sign_detached("hello world", SEED)
    b = crypto.sign_detached("hello world", SEED)
    assert a == b
    assert len(a) == 128  # 64-byte signature as hex


def test_sign_verify_roundtrip():
    pub = crypto.get_public_key(SEED)
    sig = crypto.sign_detached("attest me", SEED)
    assert crypto.verify_detached(sig, "attest me", pub) is True
    assert crypto.verify_detached(sig, "attest ME", pub) is False


def test_verify_rejects_malformed_signature():
    pub = crypto.get_public_key(SEED)
    assert crypto.verify_detached("not-hex", "msg", pub) is False


def test_generate_key_pair_roundtrips():
    priv, pub = crypto.generate_key_pair()
    assert crypto.get_public_key(priv) == pub
    sig = crypto.sign_detached("x", priv)
    assert crypto.verify_detached(sig, "x", pub)


def test_seed_must_be_32_bytes():
    with pytest.raises(ValueError):
        crypto.sign_detached("x", "42" * 16)
