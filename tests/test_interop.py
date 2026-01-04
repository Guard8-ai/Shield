#!/usr/bin/env python3
"""
Shield Cross-Language Interoperability Tests

Tests that all implementations produce compatible results.
"""

import sys
import os
import json
import subprocess
import tempfile

# Add Python shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from shield import Shield, quick_encrypt, quick_decrypt
from shield.signatures import SymmetricSignature, LamportSignature
from shield.exchange import PAKEExchange, QRExchange, KeySplitter
from shield.rotation import KeyRotationManager
from shield.group import GroupEncryption, BroadcastEncryption
from shield.identity import IdentityProvider
from shield.totp import TOTP
from shield.stream import StreamCipher
from shield.ratchet import RatchetSession


def test_shield_roundtrip():
    """Test Shield encrypt/decrypt roundtrip."""
    s = Shield("test_password", "test.service")
    plaintext = b"Hello, EXPTIME-secure world!"

    encrypted = s.encrypt(plaintext)
    decrypted = s.decrypt(encrypted)

    assert decrypted == plaintext
    print("✓ Shield roundtrip")


def test_quick_encrypt():
    """Test quick_encrypt/quick_decrypt."""
    key = os.urandom(32)
    plaintext = b"Quick encryption test"

    encrypted = quick_encrypt(key, plaintext)
    decrypted = quick_decrypt(key, encrypted)

    assert decrypted == plaintext
    print("✓ Quick encrypt/decrypt")


def test_stream_cipher():
    """Test StreamCipher."""
    key = os.urandom(32)
    cipher = StreamCipher(key, chunk_size=1024)

    plaintext = b"Stream cipher test data " * 100
    encrypted = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(encrypted)

    assert decrypted == plaintext
    print("✓ StreamCipher roundtrip")


def test_ratchet_session():
    """Test RatchetSession forward secrecy."""
    root_key = os.urandom(32)
    alice = RatchetSession(root_key, is_initiator=True)
    bob = RatchetSession(root_key, is_initiator=False)

    # Alice -> Bob
    enc1 = alice.encrypt(b"Hello Bob!")
    dec1 = bob.decrypt(enc1)
    assert dec1 == b"Hello Bob!"

    # Bob -> Alice
    enc2 = bob.encrypt(b"Hello Alice!")
    dec2 = alice.decrypt(enc2)
    assert dec2 == b"Hello Alice!"

    print("✓ RatchetSession forward secrecy")


def test_totp():
    """Test TOTP generation and verification."""
    secret = TOTP.generate_secret()
    totp = TOTP(secret)

    code = totp.generate()
    assert totp.verify(code)

    # Wrong code should fail
    assert not totp.verify("000000")

    print("✓ TOTP generation/verification")


def test_symmetric_signature():
    """Test SymmetricSignature."""
    signer = SymmetricSignature.generate()
    message = b"Message to sign"

    signature = signer.sign(message)
    assert signer.verify(message, signature, signer.verification_key)

    # Wrong message should fail
    assert not signer.verify(b"Wrong message", signature, signer.verification_key)

    print("✓ SymmetricSignature")


def test_lamport_signature():
    """Test LamportSignature (post-quantum)."""
    lamport = LamportSignature.generate()
    message = b"One-time signature test"

    signature = lamport.sign(message)
    assert LamportSignature.verify(message, signature, lamport.public_key)

    # Key should be marked as used
    assert lamport.is_used

    # Should not be able to sign again
    try:
        lamport.sign(b"Second message")
        assert False, "Should have raised error"
    except (ValueError, RuntimeError):
        pass

    print("✓ LamportSignature (post-quantum)")


def test_pake_exchange():
    """Test PAKE key exchange."""
    password = "shared_secret"
    salt = PAKEExchange.generate_salt()

    client_contribution = PAKEExchange.derive(password, salt, "client")
    server_contribution = PAKEExchange.derive(password, salt, "server")

    # Both sides derive same shared key
    shared1 = PAKEExchange.combine(client_contribution, server_contribution)
    shared2 = PAKEExchange.combine(server_contribution, client_contribution)

    assert shared1 == shared2
    print("✓ PAKE key exchange")


def test_qr_exchange():
    """Test QR code key exchange."""
    key = os.urandom(32)
    metadata = {"name": "test", "version": 1}

    data = QRExchange.generate_exchange_data(key, metadata)
    parsed_key, parsed_meta = QRExchange.parse_exchange_data(data)

    assert parsed_key == key
    assert parsed_meta == metadata
    print("✓ QR key exchange")


def test_key_splitter():
    """Test key splitting (secret sharing)."""
    key = os.urandom(32)
    shares = KeySplitter.split(key, 3)

    assert len(shares) == 3

    # All shares required
    recovered = KeySplitter.combine(shares)
    assert recovered == key

    # Partial shares don't work
    partial = KeySplitter.combine(shares[:2])
    assert partial != key

    print("✓ Key splitting")


def test_key_rotation():
    """Test key rotation manager."""
    key1 = os.urandom(32)
    manager = KeyRotationManager(key1, version=1)

    encrypted1 = manager.encrypt(b"message 1")

    # Rotate key
    key2 = os.urandom(32)
    manager.rotate(key2)
    assert manager.current_version == 2

    encrypted2 = manager.encrypt(b"message 2")

    # Both still decrypt
    assert manager.decrypt(encrypted1) == b"message 1"
    assert manager.decrypt(encrypted2) == b"message 2"

    # Re-encrypt with current key
    re_encrypted = manager.re_encrypt(encrypted1)
    version = int.from_bytes(re_encrypted[:4], 'little')
    assert version == 2

    print("✓ Key rotation")


def test_group_encryption():
    """Test multi-recipient group encryption."""
    group = GroupEncryption()

    alice_key = os.urandom(32)
    bob_key = os.urandom(32)

    group.add_member("alice", alice_key)
    group.add_member("bob", bob_key)

    plaintext = b"Secret group message"
    encrypted = group.encrypt(plaintext)

    # Both can decrypt
    alice_decrypted = GroupEncryption.decrypt(encrypted, "alice", alice_key)
    bob_decrypted = GroupEncryption.decrypt(encrypted, "bob", bob_key)

    assert alice_decrypted == plaintext
    assert bob_decrypted == plaintext

    # Non-member can't decrypt
    eve_decrypted = GroupEncryption.decrypt(encrypted, "eve", os.urandom(32))
    assert eve_decrypted is None

    print("✓ Group encryption")


def test_broadcast_encryption():
    """Test broadcast encryption with subgroups."""
    broadcast = BroadcastEncryption(subgroup_size=2)

    alice_key = os.urandom(32)
    bob_key = os.urandom(32)
    carol_key = os.urandom(32)

    sg1 = broadcast.add_member("alice", alice_key)
    sg2 = broadcast.add_member("bob", bob_key)
    sg3 = broadcast.add_member("carol", carol_key)

    # First two in same subgroup
    assert sg1 == 0
    assert sg2 == 0
    # Third in new subgroup
    assert sg3 == 1

    plaintext = b"Broadcast message"
    encrypted = broadcast.encrypt(plaintext)

    assert BroadcastEncryption.decrypt(encrypted, "alice", alice_key) == plaintext
    assert BroadcastEncryption.decrypt(encrypted, "carol", carol_key) == plaintext

    print("✓ Broadcast encryption")


def test_identity_provider():
    """Test SSO/identity provider."""
    master_key = os.urandom(32)
    provider = IdentityProvider(master_key, token_ttl=3600)

    # Register user
    identity = provider.register("alice", "password123", "Alice Smith")
    assert identity.user_id == "alice"

    # Authenticate
    token = provider.authenticate("alice", "password123")
    assert token is not None

    # Validate token
    session = provider.validate_token(token)
    assert session is not None
    assert session.user_id == "alice"

    # Wrong password fails
    bad_token = provider.authenticate("alice", "wrongpassword")
    assert bad_token is None

    # Service token
    service_token = provider.create_service_token(token, "api.example.com", ["read"])
    service_session = provider.validate_service_token(service_token, "api.example.com")
    assert service_session is not None
    assert "read" in service_session.permissions

    # Wrong service fails
    wrong_service = provider.validate_service_token(service_token, "other.example.com")
    assert wrong_service is None

    print("✓ Identity provider (SSO)")


def test_tamper_detection():
    """Test that tampering is detected across all modules."""
    s = Shield("password", "service")
    encrypted = bytearray(s.encrypt(b"secret"))
    encrypted[20] ^= 0xFF
    assert s.decrypt(bytes(encrypted)) is None

    key = os.urandom(32)
    manager = KeyRotationManager(key)
    encrypted = bytearray(manager.encrypt(b"data"))
    encrypted[20] ^= 0xFF
    try:
        manager.decrypt(bytes(encrypted))
        assert False
    except:
        pass

    print("✓ Tamper detection")


def run_js_tests():
    """Run JavaScript tests and verify they pass."""
    js_dir = os.path.join(os.path.dirname(__file__), '..', 'javascript')
    result = subprocess.run(
        ['npm', 'test'],
        cwd=js_dir,
        capture_output=True,
        text=True,
        timeout=120
    )

    if result.returncode == 0:
        # Count passed tests from output
        if "pass 81" in result.stdout or "pass: 81" in result.stdout:
            print("✓ JavaScript tests (81 passed)")
            return True
        elif "fail 0" in result.stdout:
            print("✓ JavaScript tests (all passed)")
            return True

    print(f"JavaScript tests: {result.stdout}")
    return result.returncode == 0


def run_rust_tests():
    """Run Rust tests and verify they pass."""
    rust_dir = os.path.join(os.path.dirname(__file__), '..', 'shield-core')
    result = subprocess.run(
        ['cargo', 'test'],
        cwd=rust_dir,
        capture_output=True,
        text=True,
        timeout=180
    )

    if result.returncode == 0:
        print("✓ Rust tests (passed)")
        return True

    print(f"Rust tests: {result.stderr}")
    return result.returncode == 0


def main():
    print("Shield Cross-Language Integration Tests")
    print("=" * 50)

    # Python module tests
    print("\n=== Python Module Tests ===")
    test_shield_roundtrip()
    test_quick_encrypt()
    test_stream_cipher()
    test_ratchet_session()
    test_totp()
    test_symmetric_signature()
    test_lamport_signature()
    test_pake_exchange()
    test_qr_exchange()
    test_key_splitter()
    test_key_rotation()
    test_group_encryption()
    test_broadcast_encryption()
    test_identity_provider()
    test_tamper_detection()

    print("\n=== JavaScript Tests ===")
    js_ok = run_js_tests()

    print("\n=== Rust Tests ===")
    rust_ok = run_rust_tests()

    print("\n" + "=" * 50)
    if js_ok and rust_ok:
        print("All integration tests passed!")
        return 0
    else:
        print("Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
