#!/usr/bin/env python3
"""
Shield Interoperability Tests

Exercises the Python implementation of the new (v3) wire format and prints
component-level test vectors other languages can verify against.

New wire format:
  Password mode:  version(0x02) || salt(16) || nonce(16) || ciphertext || mac(16)
  Pre-shared key: version(0x12) || nonce(16) || ciphertext || mac(16)
  MAC = HMAC-SHA256(mac_key, version || [salt] || nonce || ciphertext)[:16]
  Key derivation: PBKDF2-HMAC-SHA256(password, salt || service, 600000, 32)
                  with a per-instance RANDOM salt stored in the header.
"""

import sys
import os
import hashlib
import hmac
import struct

# Add parent to path for shield imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from shield import Shield
from shield.core import (
    SALT_SIZE,
    NONCE_SIZE,
    MAC_SIZE,
    COUNTER_SIZE,
    V2_HEADER_SIZE,
    MIN_PADDING,
    MAX_PADDING,
    VERSION_PASSWORD,
    VERSION_KEY,
    PBKDF2_ITERATIONS,
    _generate_keystream,
)


def test_python_roundtrip():
    """Test Python encrypt/decrypt roundtrip."""
    s = Shield("test_password", "test.service")
    plaintext = b"Hello, Shield interop world!"

    encrypted = s.encrypt(plaintext)
    decrypted = s.decrypt(encrypted)

    assert decrypted == plaintext, f"Roundtrip failed: {decrypted} != {plaintext}"
    print("✓ Python roundtrip")


def test_format():
    """Verify password-mode ciphertext format matches the new structure.

    Layout: version(1) || salt(16) || nonce(16) || ciphertext || mac(16)
    Inner (XOR) payload: counter(8) || timestamp(8) || pad_len(1) || pad || plaintext
    so the minimum size is 49 (overhead) + 17 (inner header) + 32 (min pad) + len(pt).
    """
    s = Shield("password", "service")
    plaintext = b"test"
    encrypted = s.encrypt(plaintext)

    overhead = 1 + SALT_SIZE + NONCE_SIZE + MAC_SIZE  # 49
    min_inner = V2_HEADER_SIZE + MIN_PADDING + len(plaintext)
    max_inner = V2_HEADER_SIZE + MAX_PADDING + len(plaintext)

    assert encrypted[0] == VERSION_PASSWORD, "Version byte should be 0x02"
    assert overhead + min_inner <= len(encrypted) <= overhead + max_inner, \
        f"Length {len(encrypted)} outside expected range"

    version = encrypted[0]
    salt = encrypted[1:1 + SALT_SIZE]
    nonce = encrypted[1 + SALT_SIZE:1 + SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted[1 + SALT_SIZE + NONCE_SIZE:-MAC_SIZE]
    mac = encrypted[-MAC_SIZE:]

    assert version == 0x02, "Version should be 0x02"
    assert len(salt) == 16, "Salt should be 16 bytes"
    assert len(nonce) == 16, "Nonce should be 16 bytes"
    assert len(mac) == 16, "MAC should be 16 bytes"
    # ciphertext length == inner payload length (XOR keystream, no expansion)
    assert len(ciphertext) >= V2_HEADER_SIZE + MIN_PADDING + len(plaintext)

    print("✓ Format verification")


def test_key_derivation():
    """Test PBKDF2 key derivation matches the new salt||service scheme.

    The salt is now random per instance and stored in the header. To get a
    reproducible vector we pin an explicit salt and check that Shield derives
    the same key as a direct PBKDF2 over (salt || service).
    """
    password = "test_password"
    service = "test.service"
    salt = bytes(range(SALT_SIZE))  # fixed, explicit

    # Direct PBKDF2 over salt || service (matches core._derive_key)
    expected = hashlib.pbkdf2_hmac(
        'sha256', password.encode(), salt + service.encode(),
        PBKDF2_ITERATIONS, dklen=32,
    )

    s = Shield(password, service, salt=salt)
    assert s.key == expected, "Shield key does not match direct PBKDF2"
    assert len(s.key) == 32, f"Key should be 32 bytes, got {len(s.key)}"

    print(f"  Key prefix: {s.key[:8].hex()}")
    print("✓ Key derivation")


def test_keystream_determinism():
    """Test that keystream generation is deterministic."""
    key = b'\x01' * 32
    nonce = b'\x02' * 16

    ks1 = _generate_keystream(key, nonce, 64)
    ks2 = _generate_keystream(key, nonce, 64)

    assert ks1 == ks2, "Keystream should be deterministic"
    print("✓ Keystream determinism")


def test_different_passwords():
    """Test that different passwords produce different ciphertext."""
    s1 = Shield("password1", "service", max_age_ms=None)
    s2 = Shield("password2", "service", max_age_ms=None)

    plaintext = b"secret data"

    enc1 = s1.encrypt(plaintext)
    enc2 = s2.encrypt(plaintext)

    # Different keys = can't decrypt each other's messages
    assert s1.decrypt(enc2) is None, "Should not decrypt with wrong key"
    assert s2.decrypt(enc1) is None, "Should not decrypt with wrong key"

    print("✓ Different passwords isolation")


def test_different_services():
    """Test that different services produce different keys."""
    s1 = Shield("password", "service1", max_age_ms=None)
    s2 = Shield("password", "service2", max_age_ms=None)

    plaintext = b"secret data"

    enc1 = s1.encrypt(plaintext)
    enc2 = s2.encrypt(plaintext)

    # Different services = can't decrypt each other's messages
    assert s1.decrypt(enc2) is None, "Should not decrypt with wrong service"
    assert s2.decrypt(enc1) is None, "Should not decrypt with wrong service"

    print("✓ Different services isolation")


def test_tamper_detection():
    """Test that tampering is detected."""
    s = Shield("password", "service")
    encrypted = bytearray(s.encrypt(b"secret data"))

    # Tamper with ciphertext body
    encrypted[40] ^= 0xFF

    assert s.decrypt(bytes(encrypted)) is None, "Should detect tampering"
    print("✓ Tamper detection")


def print_test_vectors():
    """Print component-level test vectors for other implementations."""
    print("\n=== Test Vectors (new format) ===\n")

    password = "test_password"
    service = "test.service"
    salt = bytes(range(SALT_SIZE))  # fixed, explicit

    key = hashlib.pbkdf2_hmac(
        'sha256', password.encode(), salt + service.encode(),
        PBKDF2_ITERATIONS, dklen=32,
    )

    print(f"Password:   {password}")
    print(f"Service:    {service}")
    print(f"Salt:       {salt.hex()}")
    print(f"Iterations: {PBKDF2_ITERATIONS}")
    print(f"Key:        {key.hex()}")

    # Subkeys (HMAC domain separation)
    enc_key = hmac.new(key, b"shield-encrypt", hashlib.sha256).digest()
    mac_key = hmac.new(key, b"shield-authenticate", hashlib.sha256).digest()
    print(f"EncKey:     {enc_key.hex()}")
    print(f"MacKey:     {mac_key.hex()}")

    # Fixed nonce for reproducible keystream
    nonce = bytes(range(16))
    print(f"Nonce:      {nonce.hex()}")

    ks = _generate_keystream(enc_key, nonce, 64)
    print(f"Keystream (64 bytes): {ks.hex()}")

    print("\n=== End Test Vectors ===\n")


def main():
    print("Shield Python Interop Tests")
    print("=" * 40)

    test_python_roundtrip()
    test_format()
    test_key_derivation()
    test_keystream_determinism()
    test_different_passwords()
    test_different_services()
    test_tamper_detection()

    print_test_vectors()

    print("=" * 40)
    print("All tests passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
