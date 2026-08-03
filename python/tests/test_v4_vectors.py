"""Conformance: reproduce the Rust-generated v4 vectors byte-for-byte.

Loads tests/v4_test_vectors.json (generated from the Rust reference) and proves
the Python binding:
  1. derives the same master + AEAD keys,
  2. reproduces every deterministic ciphertext BYTE-FOR-BYTE, and
  3. decrypts every vector back to its plaintext (freshness disabled).

This is the cross-language byte-identity gate that prevents silent format drift.
"""

import json
import os

import pytest

from shield.core import (
    Shield,
    _derive_aead_key,
    _seal_deterministic,
    _open,
    SALT_SIZE,
    NONCE_SIZE,
)

VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "tests", "v4_test_vectors.json"
)


def _load():
    with open(VECTORS_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _all_vectors():
    doc = _load()
    return doc["deterministic_vectors"] + doc.get("deterministic_vectors_chacha", [])


def _master_for(vec):
    if vec["mode"] == "password":
        kdf_salt = bytes.fromhex(vec["salt_hex"])
        s = Shield(vec["password"], vec["service"], salt=kdf_salt,
                   iterations=vec["iterations"])
        return s.key
    return bytes.fromhex(vec["key_hex"])


@pytest.mark.parametrize("vec", _all_vectors(), ids=lambda v: v["name"])
def test_kdf_matches(vec):
    master = _master_for(vec)
    assert master.hex() == vec["master_key_hex"], "master key drift"
    assert _derive_aead_key(master).hex() == vec["aead_key_hex"], "AEAD key drift"


@pytest.mark.parametrize("vec", _all_vectors(), ids=lambda v: v["name"])
def test_reproduce_bytes(vec):
    """Reproduce expected_output_hex byte-for-byte from the deterministic seal."""
    suite = int(vec["suite"], 16)
    master = _master_for(vec)
    aead_key = _derive_aead_key(master)
    salt = bytes.fromhex(vec["salt_hex"]) if vec["mode"] == "password" else None
    nonce = bytes.fromhex(vec["nonce_hex"])
    padding = bytes.fromhex(vec["padding_hex"])
    plaintext = bytes.fromhex(vec["plaintext_hex"])

    out = _seal_deterministic(
        aead_key, suite, salt, nonce, vec["timestamp_ms"], vec["pad_len"], padding, plaintext
    )
    assert out.hex() == vec["expected_output_hex"], f"byte drift in {vec['name']}"


@pytest.mark.parametrize("vec", _all_vectors(), ids=lambda v: v["name"])
def test_decrypt_vectors(vec):
    """Decrypt each vector back to plaintext (freshness window disabled)."""
    suite = int(vec["suite"], 16)
    master = _master_for(vec)
    aead_key = _derive_aead_key(master)
    encrypted = bytes.fromhex(vec["expected_output_hex"])
    aad_len = (2 + SALT_SIZE) if vec["mode"] == "password" else 2

    opened = _open(aead_key, suite, encrypted, aad_len, None)
    assert opened == bytes.fromhex(vec["plaintext_hex"]), f"decrypt failed for {vec['name']}"


def test_password_vector_via_public_decrypt():
    """A password vector decrypts through the public Shield.decrypt() API too."""
    doc = _load()
    vec = next(v for v in doc["deterministic_vectors"] if v["mode"] == "password")
    s = Shield(vec["password"], vec["service"], salt=bytes.fromhex(vec["salt_hex"]),
               iterations=vec["iterations"], max_age_ms=None)
    encrypted = bytes.fromhex(vec["expected_output_hex"])
    assert s.decrypt(encrypted) == bytes.fromhex(vec["plaintext_hex"])
