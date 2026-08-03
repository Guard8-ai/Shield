#!/usr/bin/env python3
"""
Shield Interoperability Tests (v4 format)

Exercises the Python implementation of the v4 wire format and prints
component-level test vectors other languages can verify against.

v4 wire format:
  Password mode:  version(0x03) || suite(1) || salt(16) || nonce(12) || ciphertext || tag(16)
  Pre-shared key: version(0x13) || suite(1) || nonce(12) || ciphertext || tag(16)
  Key derivation: PBKDF2-HMAC-SHA256(password, salt || service, 600000, 32)
                  then HKDF-Expand(master, "shield/aead/v4", 32) for the AEAD key.
"""

import sys
import os
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from shield import Shield
from shield.core import (
    SALT_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    MIN_PADDING,
    MAX_PADDING,
    INNER_HEADER_SIZE,
    VERSION_PASSWORD,
    VERSION_KEY,
    PBKDF2_ITERATIONS,
)


# v4 password-mode overhead (before and after the AEAD ciphertext):
#   version(1) + suite(1) + salt(16) + nonce(12) = 30 bytes before ct
#   tag(16) = 16 bytes after ct
# Total header = 30, total overhead = 46
V4_PWD_HEADER = 1 + 1 + SALT_SIZE + NONCE_SIZE   # 30
V4_OVERHEAD = V4_PWD_HEADER + TAG_SIZE             # 46


def test_python_roundtrip():
    """Test Python encrypt/decrypt roundtrip."""
    s = Shield("test_password", "test.service")
    plaintext = b"Hello, Shield interop world!"

    encrypted = s.encrypt(plaintext)
    decrypted = s.decrypt(encrypted)

    assert decrypted == plaintext, f"Roundtrip failed: {decrypted!r} != {plaintext!r}"
    print("✓ Python roundtrip")


def test_format():
    """Verify password-mode ciphertext format matches the v4 structure.

    Layout: version(1) || suite(1) || salt(16) || nonce(12) || ct+tag
    Inner plaintext: timestamp_ms(8) || pad_len(1) || padding || message
    Minimum length: V4_OVERHEAD + INNER_HEADER_SIZE + MIN_PADDING + len(plaintext)
    """
    s = Shield("password", "service")
    plaintext = b"test"
    encrypted = s.encrypt(plaintext)

    min_len = V4_OVERHEAD + INNER_HEADER_SIZE + MIN_PADDING + len(plaintext)
    max_len = V4_OVERHEAD + INNER_HEADER_SIZE + MAX_PADDING + len(plaintext)

    assert encrypted[0] == VERSION_PASSWORD, \
        f"Version byte should be {VERSION_PASSWORD:#x}, got {encrypted[0]:#x}"
    assert min_len <= len(encrypted) <= max_len, \
        f"Length {len(encrypted)} outside expected range [{min_len}, {max_len}]"

    version = encrypted[0]
    suite = encrypted[1]
    salt = encrypted[2:2 + SALT_SIZE]
    nonce = encrypted[2 + SALT_SIZE:2 + SALT_SIZE + NONCE_SIZE]
    tag = encrypted[-TAG_SIZE:]

    assert version == VERSION_PASSWORD, f"Version should be {VERSION_PASSWORD:#x}"
    assert suite in (0x01, 0x02), f"Unknown suite {suite:#x}"
    assert len(salt) == SALT_SIZE, f"Salt should be {SALT_SIZE} bytes"
    assert len(nonce) == NONCE_SIZE, f"Nonce should be {NONCE_SIZE} bytes"
    assert len(tag) == TAG_SIZE, f"Tag should be {TAG_SIZE} bytes"
    print("✓ v4 format structure")


def test_ciphertext_randomness():
    """Two encryptions of the same plaintext must produce different ciphertext."""
    s = Shield("password", "service")
    plaintext = b"same plaintext"
    enc1 = s.encrypt(plaintext)
    enc2 = s.encrypt(plaintext)
    assert enc1 != enc2, "Two encryptions of the same plaintext should differ"
    print("✓ Ciphertext randomness")


def test_key_derivation():
    """Test PBKDF2 key derivation matches the v4 scheme.

    The master key is PBKDF2-HMAC-SHA256(password, salt || service, iterations).
    """
    password = "test_password"
    service = "test.service"
    salt = bytes(range(SALT_SIZE))  # pinned explicit salt

    expected = hashlib.pbkdf2_hmac(
        'sha256', password.encode(), salt + service.encode(),
        PBKDF2_ITERATIONS, dklen=32,
    )

    s = Shield(password, service, salt=salt)
    assert s.key == expected, "Shield key does not match direct PBKDF2"
    assert len(s.key) == 32, f"Key should be 32 bytes, got {len(s.key)}"
    print("✓ Key derivation")


def test_different_passwords():
    """Different passwords must not decrypt each other's ciphertext."""
    s1 = Shield("password1", "service", max_age_ms=None)
    s2 = Shield("password2", "service", max_age_ms=None)
    plaintext = b"secret data"
    enc1 = s1.encrypt(plaintext)
    enc2 = s2.encrypt(plaintext)
    assert s1.decrypt(enc2) is None, "Should not decrypt with wrong password"
    assert s2.decrypt(enc1) is None, "Should not decrypt with wrong password"
    print("✓ Different passwords isolation")


def test_different_services():
    """Different services must not decrypt each other's ciphertext."""
    s1 = Shield("password", "service1", max_age_ms=None)
    s2 = Shield("password", "service2", max_age_ms=None)
    plaintext = b"secret data"
    enc1 = s1.encrypt(plaintext)
    enc2 = s2.encrypt(plaintext)
    assert s1.decrypt(enc2) is None, "Should not decrypt with wrong service"
    assert s2.decrypt(enc1) is None, "Should not decrypt with wrong service"
    print("✓ Different services isolation")


def test_tamper_detection():
    """Any bit flip in the ciphertext must cause authentication failure."""
    s = Shield("password", "service")
    encrypted = bytearray(s.encrypt(b"secret data"))
    encrypted[40] ^= 0xFF
    result = s.decrypt(bytes(encrypted))
    assert result is None, "Should detect tampering"
    print("✓ Tamper detection")


def test_empty_plaintext():
    """Empty plaintext should encrypt and decrypt correctly."""
    s = Shield("password", "service", max_age_ms=None)
    plaintext = b""
    encrypted = s.encrypt(plaintext)
    decrypted = s.decrypt(encrypted)
    assert decrypted == plaintext, f"Empty roundtrip failed: {decrypted!r}"
    print("✓ Empty plaintext")


def test_large_plaintext():
    """Large plaintext should encrypt and decrypt correctly."""
    s = Shield("password", "service", max_age_ms=None)
    plaintext = b"X" * 100_000
    encrypted = s.encrypt(plaintext)
    decrypted = s.decrypt(encrypted)
    assert decrypted == plaintext, "Large plaintext roundtrip failed"
    print("✓ Large plaintext")


def test_key_mode():
    """Pre-shared key mode should encrypt/decrypt correctly."""
    key = bytes(range(32))
    s = Shield.with_key(key, max_age_ms=None)
    plaintext = b"key-mode test"
    encrypted = s.encrypt(plaintext)
    assert encrypted[0] == VERSION_KEY, \
        f"Key-mode version should be {VERSION_KEY:#x}, got {encrypted[0]:#x}"
    decrypted = s.decrypt(encrypted)
    assert decrypted == plaintext, f"Key-mode roundtrip failed: {decrypted!r}"
    print("✓ Key mode")


def main():
    print("Shield Python Interop Tests (v4)")
    print("=" * 40)

    test_python_roundtrip()
    test_format()
    test_ciphertext_randomness()
    test_key_derivation()
    test_different_passwords()
    test_different_services()
    test_tamper_detection()
    test_empty_plaintext()
    test_large_plaintext()
    test_key_mode()

    print("=" * 40)
    print("All tests passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
