"""
Within-family ratchet vector validation.

Tests that the Python (Family B) implementation produces exactly the
intermediate keys and ciphertext defined in ratchet_vectors_family_b.json.

Family B covers: python, javascript, kotlin, android, ios.
All bindings in this family MUST produce byte-identical outputs given the
same initial chain_key; these vectors are the ground truth.

Cross-family tests are intentionally absent — Family A (Rust/WASM) and
Family C (Go/Java/Swift/C#/C) use different KDFs and are NOT compatible.
"""

import hashlib
import hmac as hmac_mod
import json
import struct
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).parent
REPO_ROOT = TESTS_DIR.parent

# Make the python package importable without installation
sys.path.insert(0, str(REPO_ROOT / "python"))


# ---------------------------------------------------------------------------
# Helpers — re-implement the Family B primitives directly so the test does
# NOT depend on the Python binding's internal structure (the binding is what
# we are VALIDATING against the vectors, not the other way around).
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    ks = b""
    for i in range((length + 31) // 32):
        ks += _sha256(key + nonce + struct.pack("<I", i))
    return ks[:length]


def _family_b_decrypt(msg_key: bytes, encrypted: bytes):
    """Decrypt a Family B frame; returns (plaintext, counter) or raises."""
    assert len(encrypted) >= 40, "frame too short"
    nonce = encrypted[:16]
    ciphertext = encrypted[16:-16]
    mac = encrypted[-16:]

    expected_mac = hmac_mod.new(msg_key, nonce + ciphertext, hashlib.sha256).digest()[:16]
    assert hmac_mod.compare_digest(mac, expected_mac), "MAC verification failed"

    keystream = _generate_keystream(msg_key, nonce, len(ciphertext))
    decrypted = bytes(c ^ k for c, k in zip(ciphertext, keystream))

    counter = struct.unpack("<Q", decrypted[:8])[0]
    return decrypted[8:], counter


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _load_family_b():
    path = TESTS_DIR / "ratchet_vectors_family_b.json"
    if not path.exists():
        raise FileNotFoundError(f"Vector file not found: {path}")
    return json.loads(path.read_text())


def test_family_b_chain_step():
    """Verify SHA256 chain derivation matches the stored intermediate values."""
    data = _load_family_b()
    root_key = bytes.fromhex(data["vectors"][0]["root_key"])

    # Initial send chain: SHA256(root || "send")
    send_chain_init = _sha256(root_key + b"send")
    expected_init = data["vectors"][0]["intermediate"]["send_chain_after_init"]
    assert send_chain_init.hex() == expected_init, (
        f"send_chain_after_init mismatch\n"
        f"  got:      {send_chain_init.hex()}\n"
        f"  expected: {expected_init}"
    )

    # Chain step: msg_key = SHA256(chain || "message")
    msg_key = _sha256(send_chain_init + b"message")
    expected_msg_key = data["vectors"][0]["intermediate"]["msg_key"]
    assert msg_key.hex() == expected_msg_key, (
        f"msg_key mismatch\n"
        f"  got:      {msg_key.hex()}\n"
        f"  expected: {expected_msg_key}"
    )

    # new_chain = SHA256(chain || "chain")
    new_chain = _sha256(send_chain_init + b"chain")
    expected_new_chain = data["vectors"][0]["intermediate"]["new_send_chain"]
    assert new_chain.hex() == expected_new_chain, (
        f"new_send_chain mismatch\n"
        f"  got:      {new_chain.hex()}\n"
        f"  expected: {expected_new_chain}"
    )


def test_family_b_ciphertext():
    """Verify that re-encrypting with the fixed nonce reproduces the stored ciphertext."""
    data = _load_family_b()
    vec = data["vectors"][0]

    root_key = bytes.fromhex(vec["root_key"])
    plaintext = bytes.fromhex(vec["plaintext_hex"])
    fixed_nonce = bytes.fromhex(vec["fixed_nonce_hex"])
    counter = vec["counter"]
    expected_ct = bytes.fromhex(vec["ciphertext_hex"])

    send_chain_init = _sha256(root_key + b"send")
    msg_key = _sha256(send_chain_init + b"message")

    counter_bytes = struct.pack("<Q", counter)
    data_buf = counter_bytes + plaintext
    ks = _generate_keystream(msg_key, fixed_nonce, len(data_buf))
    ct_inner = bytes(p ^ k for p, k in zip(data_buf, ks))
    mac = hmac_mod.new(msg_key, fixed_nonce + ct_inner, hashlib.sha256).digest()[:16]
    encrypted = fixed_nonce + ct_inner + mac

    assert encrypted == expected_ct, (
        f"ciphertext mismatch\n"
        f"  got:      {encrypted.hex()}\n"
        f"  expected: {expected_ct.hex()}"
    )


def test_family_b_decrypt():
    """Verify Bob can decrypt Alice's stored ciphertext."""
    data = _load_family_b()
    vec = data["vectors"][0]

    root_key = bytes.fromhex(vec["root_key"])
    expected_plaintext = bytes.fromhex(vec["plaintext_hex"])
    ciphertext = bytes.fromhex(vec["ciphertext_hex"])

    # Bob (non-initiator) recv_chain = SHA256(root || "send") — same as Alice's send
    bob_recv_chain = _sha256(root_key + b"send")
    bob_msg_key = _sha256(bob_recv_chain + b"message")

    plaintext, counter = _family_b_decrypt(bob_msg_key, ciphertext)
    assert counter == vec["counter"], f"counter mismatch: got {counter}, expected {vec['counter']}"
    assert plaintext == expected_plaintext, (
        f"plaintext mismatch\n"
        f"  got:      {plaintext!r}\n"
        f"  expected: {expected_plaintext!r}"
    )


def test_family_b_python_binding():
    """
    Validate the Python RatchetSession binding against the stored vectors.

    Uses a fixed nonce injected via monkeypatching os.urandom so the output
    is deterministic and matches the vector file.
    """
    import os
    from unittest.mock import patch

    data_json = _load_family_b()
    vec = data_json["vectors"][0]
    fixed_nonce = bytes.fromhex(vec["fixed_nonce_hex"])
    root_key = bytes.fromhex(vec["root_key"])
    expected_plaintext = bytes.fromhex(vec["plaintext_hex"])
    expected_ct = bytes.fromhex(vec["ciphertext_hex"])

    try:
        from shield.ratchet import RatchetSession
    except ImportError:
        import pytest
        pytest.skip("shield.ratchet not importable — python binding not installed")

    with patch("os.urandom", return_value=fixed_nonce):
        alice = RatchetSession(root_key, is_initiator=True)
        ct = alice.encrypt(expected_plaintext)

    assert ct == expected_ct, (
        f"Python binding produced wrong ciphertext\n"
        f"  got:      {ct.hex()}\n"
        f"  expected: {expected_ct.hex()}"
    )

    # Bob decrypts
    with patch("os.urandom", return_value=fixed_nonce):
        bob = RatchetSession(root_key, is_initiator=False)
        plaintext = bob.decrypt(ct)

    assert plaintext == expected_plaintext, (
        f"Python binding decryption failed\n"
        f"  got:      {plaintext!r}\n"
        f"  expected: {expected_plaintext!r}"
    )
