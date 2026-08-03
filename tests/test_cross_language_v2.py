#!/usr/bin/env python3
"""
Cross-Language V4 Interoperability Tests (standard AEAD)

Validates the v4 wire format against the shared conformance vectors generated
from the Rust reference (tests/v4_test_vectors.json):
- Password mode:  0x03 || suite(1) || salt(16) || nonce(12) || ciphertext||tag
- Pre-shared key: 0x13 || suite(1) || nonce(12) || ciphertext||tag
- AEAD: AES-256-GCM (suite 0x01) or ChaCha20-Poly1305 (suite 0x02)
- KDF: PBKDF2-HMAC-SHA256(600k) -> HKDF-SHA256-Expand("shield/aead/v4", 32)
- Inner plaintext: timestamp_ms(8) || pad_len(1) || padding(32-128) || message
- Old v3 ciphertexts (0x02/0x12) are HARD-REJECTED (clean break)

The same vectors are reproduced byte-for-byte and decrypted by the Rust, Go and
JavaScript bindings (see each binding's own conformance test), which is the
cross-language byte-identity guarantee.

Run: python3 tests/test_cross_language_v2.py
"""

import sys
import json
from pathlib import Path

# Add python module to path
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from shield.core import (  # noqa: E402
    Shield,
    _derive_aead_key,
    _seal_deterministic,
    _open,
    INNER_HEADER_SIZE,
    MIN_PADDING,
    MAX_PADDING,
    NONCE_SIZE,
    TAG_SIZE,
    SALT_SIZE,
    VERSION_PASSWORD,
    VERSION_KEY,
    SUITE_AES_256_GCM,
    SUITE_CHACHA20_POLY1305,
    PBKDF2_ITERATIONS,
)

# Fixed v4 overheads around the AEAD body.
PASSWORD_OVERHEAD = 2 + SALT_SIZE + NONCE_SIZE + TAG_SIZE  # 46
KEY_OVERHEAD = 2 + NONCE_SIZE + TAG_SIZE                   # 30


def load_v4_vectors():
    with open(Path(__file__).parent / "v4_test_vectors.json", "r", encoding="utf-8") as f:
        return json.load(f)


def all_vectors(doc):
    return doc["deterministic_vectors"] + doc.get("deterministic_vectors_chacha", [])


def suite_byte(v):
    return int(v["suite"], 16)


def master_for(v):
    if v["mode"] == "password":
        s = Shield(v["password"], v["service"], salt=bytes.fromhex(v["salt_hex"]),
                   iterations=v["iterations"])
        return s.key
    return bytes.fromhex(v["key_hex"])


def test_v4_basic_roundtrip():
    print("Testing v4 basic roundtrip...")
    shield = Shield("test-password", "test.example.com", max_age_ms=60000)
    plaintext = b"Hello, Shield v4!"
    encrypted = shield.encrypt(plaintext)
    min_size = PASSWORD_OVERHEAD + INNER_HEADER_SIZE + MIN_PADDING + len(plaintext)
    assert len(encrypted) >= min_size, f"too short: {len(encrypted)} < {min_size}"
    assert encrypted[0] == VERSION_PASSWORD, "password mode must start with 0x03"
    assert encrypted[1] == SUITE_AES_256_GCM, "default suite must be AES-256-GCM"
    assert shield.decrypt(encrypted) == plaintext, "roundtrip failed"
    print("  ✓ v4 roundtrip successful")


def test_v4_length_variation():
    print("Testing v4 length variation...")
    shield = Shield("test-password", "test.example.com", max_age_ms=60000)
    lengths = {len(shield.encrypt(b"Same message every time")) for _ in range(10)}
    assert len(lengths) > 1, f"expected length variation, got {len(lengths)}"
    print(f"  ✓ {len(lengths)} unique lengths from 10 encryptions")


def test_per_instance_random_salt():
    print("Testing per-instance random salt...")
    a = Shield("test-password", "test.example.com")
    b = Shield("test-password", "test.example.com")
    ca = a.encrypt(b"x")
    cb = b.encrypt(b"x")
    # Salt lives at bytes [2:18] of a v4 password-mode ciphertext.
    assert ca[2:2 + SALT_SIZE] != cb[2:2 + SALT_SIZE], "per-instance salts must differ"
    assert a.key != b.key, "per-instance keys must differ"
    assert b.decrypt(a.encrypt(b"hi")) == b"hi", "cross-instance decrypt should work"
    print("  ✓ random per-instance salt confirmed")


def test_legacy_formats_hard_rejected():
    print("Testing legacy-format hard rejection...")
    shield = Shield("test-password", "test.example.com", max_age_ms=None)
    # v3 password ciphertexts began with 0x02; must be rejected by v4.
    assert shield.decrypt(bytes([0x02]) + b"\x00" * 80) is None
    assert shield.decrypt(bytes([0x12]) + b"\x00" * 80) is None
    ct = shield.encrypt(b"data")
    assert shield.decrypt(bytes([0xFF]) + ct[1:]) is None
    print("  ✓ legacy / unknown formats hard-rejected")


def test_constants_match_spec():
    print("Testing constants match spec...")
    assert INNER_HEADER_SIZE == 9
    assert MIN_PADDING == 32 and MAX_PADDING == 128
    assert NONCE_SIZE == 12 and TAG_SIZE == 16 and SALT_SIZE == 16
    assert VERSION_PASSWORD == 0x03 and VERSION_KEY == 0x13
    assert SUITE_AES_256_GCM == 0x01 and SUITE_CHACHA20_POLY1305 == 0x02
    assert PBKDF2_ITERATIONS == 600000
    print("  ✓ all constants match specification")


def test_kdf_vectors():
    print("Testing KDF vectors (master + AEAD key)...")
    doc = load_v4_vectors()
    count = 0
    for v in all_vectors(doc):
        master = master_for(v)
        assert master.hex() == v["master_key_hex"], f"master drift {v['name']}"
        assert _derive_aead_key(master).hex() == v["aead_key_hex"], f"aead drift {v['name']}"
        count += 1
    print(f"  ✓ {count} KDF vectors verified")


def test_reproduce_vectors_byte_for_byte():
    print("Testing byte-for-byte vector reproduction...")
    doc = load_v4_vectors()
    count = 0
    for v in all_vectors(doc):
        aead_key = _derive_aead_key(master_for(v))
        salt = bytes.fromhex(v["salt_hex"]) if v["mode"] == "password" else None
        out = _seal_deterministic(
            aead_key, suite_byte(v), salt, bytes.fromhex(v["nonce_hex"]),
            v["timestamp_ms"], v["pad_len"], bytes.fromhex(v["padding_hex"]),
            bytes.fromhex(v["plaintext_hex"]),
        )
        assert out.hex() == v["expected_output_hex"], f"BYTE DRIFT {v['name']}"
        count += 1
    print(f"  ✓ {count} vectors reproduced byte-for-byte")


def test_decrypt_vectors():
    print("Testing decrypt of shared vectors...")
    doc = load_v4_vectors()
    count = 0
    for v in all_vectors(doc):
        aead_key = _derive_aead_key(master_for(v))
        encrypted = bytes.fromhex(v["expected_output_hex"])
        aad_len = (2 + SALT_SIZE) if v["mode"] == "password" else 2
        opened = _open(aead_key, suite_byte(v), encrypted, aad_len, None)
        assert opened == bytes.fromhex(v["plaintext_hex"]), f"decrypt failed {v['name']}"
        count += 1
    print(f"  ✓ {count} vectors decrypted to expected plaintext")


def run_all_tests():
    print("\n" + "=" * 70)
    print("Shield V4 Cross-Language Interoperability Tests (standard AEAD)")
    print("=" * 70 + "\n")

    tests = [
        test_v4_basic_roundtrip,
        test_v4_length_variation,
        test_per_instance_random_salt,
        test_legacy_formats_hard_rejected,
        test_constants_match_spec,
        test_kdf_vectors,
        test_reproduce_vectors_byte_for_byte,
        test_decrypt_vectors,
    ]

    passed = failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:  # noqa: BLE001
            print(f"  ✗ FAILED: {test.__name__}: {e}")
            failed += 1

    print("\n" + "=" * 70)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 70 + "\n")
    return failed == 0


if __name__ == "__main__":
    sys.exit(0 if run_all_tests() else 1)
