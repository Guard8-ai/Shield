#!/usr/bin/env python3
"""
Shield Interoperability Tests (v4 format)

Tests that the Python implementation correctly implements the v4 AEAD format.
Run standalone: python tests/interop.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from shield import Shield


# v4 overhead: version(1)+suite(1)+salt(32)+nonce(12)+timestamp(8)+pad_len(1)+tag(16) = 71
# Plus random padding in [32, 128]. Total overhead: 103..199 bytes per ciphertext.
V4_MIN_OVERHEAD = 103
V4_MAX_OVERHEAD = 199


def test_python_roundtrip():
    """Test Python encrypt/decrypt roundtrip."""
    s = Shield("test_password", "test.service")
    plaintext = b"Hello, Shield v4!"

    encrypted = s.encrypt(plaintext)
    decrypted = s.decrypt(encrypted)

    assert decrypted == plaintext, f"Roundtrip failed: {decrypted!r} != {plaintext!r}"
    print("✓ Python roundtrip")


def test_format():
    """Verify v4 ciphertext is within the expected size range."""
    s = Shield("password", "service")
    plaintext = b"test"
    encrypted = s.encrypt(plaintext)

    min_size = len(plaintext) + V4_MIN_OVERHEAD
    max_size = len(plaintext) + V4_MAX_OVERHEAD
    assert min_size <= len(encrypted) <= max_size, (
        f"v4 ciphertext size {len(encrypted)} outside expected range [{min_size}, {max_size}]"
    )

    # Ciphertext must be distinct from plaintext.
    assert encrypted != plaintext, "Encrypted must differ from plaintext"
    print(f"✓ Format verification (size={len(encrypted)}, expected {min_size}..{max_size})")


def test_ciphertext_randomness():
    """Two encryptions of the same plaintext must produce different ciphertext."""
    s = Shield("password", "service")
    plaintext = b"same plaintext"
    enc1 = s.encrypt(plaintext)
    enc2 = s.encrypt(plaintext)

    assert enc1 != enc2, "Ciphertext must be non-deterministic (fresh nonce+salt each time)"
    print("✓ Ciphertext randomness")


def test_different_passwords():
    """Different passwords must not decrypt each other's messages."""
    s1 = Shield("password1", "service")
    s2 = Shield("password2", "service")
    plaintext = b"secret data"

    enc1 = s1.encrypt(plaintext)
    enc2 = s2.encrypt(plaintext)

    assert s1.decrypt(enc2) is None, "Should not decrypt with wrong password"
    assert s2.decrypt(enc1) is None, "Should not decrypt with wrong password"
    print("✓ Different passwords isolation")


def test_different_services():
    """Different services must not decrypt each other's messages."""
    s1 = Shield("password", "service1")
    s2 = Shield("password", "service2")
    plaintext = b"secret data"

    enc1 = s1.encrypt(plaintext)
    enc2 = s2.encrypt(plaintext)

    assert s1.decrypt(enc2) is None, "Should not decrypt with wrong service"
    assert s2.decrypt(enc1) is None, "Should not decrypt with wrong service"
    print("✓ Different services isolation")


def test_tamper_detection():
    """Any bit flip in the ciphertext must be detected."""
    s = Shield("password", "service")
    encrypted = bytearray(s.encrypt(b"secret data"))

    encrypted[len(encrypted) // 2] ^= 0xFF

    result = s.decrypt(bytes(encrypted))
    assert result is None, "Should detect tampering"
    print("✓ Tamper detection")


def test_empty_plaintext():
    """Empty plaintext must round-trip successfully."""
    s = Shield("password", "service")
    encrypted = s.encrypt(b"")
    decrypted = s.decrypt(encrypted)
    assert decrypted == b"", f"Empty roundtrip failed: {decrypted!r}"
    print("✓ Empty plaintext roundtrip")


def test_large_plaintext():
    """Large plaintext must round-trip successfully."""
    s = Shield("password", "service")
    plaintext = b"x" * 10_000
    encrypted = s.encrypt(plaintext)
    decrypted = s.decrypt(encrypted)
    assert decrypted == plaintext, "Large plaintext roundtrip failed"
    print("✓ Large plaintext roundtrip (10 KB)")


def main():
    print("Shield Python Interop Tests (v4)")
    print("=" * 40)

    test_python_roundtrip()
    test_format()
    test_ciphertext_randomness()
    test_different_passwords()
    test_different_services()
    test_tamper_detection()
    test_empty_plaintext()
    test_large_plaintext()

    print("=" * 40)
    print("All tests passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
