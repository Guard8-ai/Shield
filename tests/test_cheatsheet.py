#!/usr/bin/env python3
"""
Test all CHEATSHEET.md examples work correctly.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))


def test_basic_encryption():
    """Test basic encryption example."""
    from shield import Shield

    s = Shield("password", "service.com")
    encrypted = s.encrypt(b"secret data")
    decrypted = s.decrypt(encrypted)

    assert decrypted == b"secret data"
    print("✓ Basic encryption")


def test_preshared_key():
    """Test pre-shared key example."""
    from shield import quick_encrypt, quick_decrypt
    import os

    key = os.urandom(32)
    encrypted = quick_encrypt(key, b"data")
    decrypted = quick_decrypt(key, encrypted)

    assert decrypted == b"data"
    print("✓ Pre-shared key")


def test_streaming():
    """Test streaming example."""
    from shield import StreamCipher

    cipher = StreamCipher.from_password("password", b"salt")
    encrypted = cipher.encrypt(b"large data " * 1000)
    decrypted = cipher.decrypt(encrypted)

    assert decrypted == b"large data " * 1000
    print("✓ Streaming")


def test_forward_secrecy():
    """Test ratchet example."""
    from shield import RatchetSession
    import os

    root_key = os.urandom(32)
    alice = RatchetSession(root_key, is_initiator=True)
    bob = RatchetSession(root_key, is_initiator=False)

    encrypted = alice.encrypt(b"Hello!")
    decrypted = bob.decrypt(encrypted)

    assert decrypted == b"Hello!"
    print("✓ Forward secrecy (ratchet)")


def test_totp():
    """Test TOTP example."""
    from shield import TOTP

    secret = TOTP.generate_secret()
    totp = TOTP(secret)
    code = totp.generate()
    is_valid = totp.verify(code)
    uri = totp.provisioning_uri("user@example.com", "MyApp")

    assert is_valid
    assert "otpauth://" in uri
    print("✓ TOTP")


def test_recovery_codes():
    """Test recovery codes example."""
    from shield.totp import RecoveryCodes

    rc = RecoveryCodes()
    codes = rc.codes
    assert len(codes) == 10
    assert rc.remaining == 10

    first_code = codes[0]
    assert rc.verify(first_code) is True
    assert rc.remaining == 9
    print("✓ Recovery codes")


def test_signatures():
    """Test signature examples (new feature)."""
    from shield.signatures import SymmetricSignature, LamportSignature

    # Symmetric
    signer = SymmetricSignature.generate()
    sig = signer.sign(b"message")
    assert signer.verify(b"message", sig, signer.verification_key)

    # Lamport
    lamport = LamportSignature.generate()
    sig = lamport.sign(b"message")
    assert LamportSignature.verify(b"message", sig, lamport.public_key)

    print("✓ Digital signatures")


def test_key_exchange():
    """Test key exchange examples (new feature)."""
    from shield.exchange import PAKEExchange, QRExchange, KeySplitter
    import os

    # PAKE
    salt = PAKEExchange.generate_salt()
    client = PAKEExchange.derive("password", salt, "client")
    server = PAKEExchange.derive("password", salt, "server")
    shared = PAKEExchange.combine(client, server)
    assert len(shared) == 32

    # QR
    key = os.urandom(32)
    data = QRExchange.generate_exchange_data(key, {"name": "test"})
    parsed_key, meta = QRExchange.parse_exchange_data(data)
    assert parsed_key == key

    # Key splitting
    shares = KeySplitter.split(key, 3)
    recovered = KeySplitter.combine(shares)
    assert recovered == key

    print("✓ Key exchange")


def test_key_rotation():
    """Test key rotation example (new feature)."""
    from shield.rotation import KeyRotationManager
    import os

    key1 = os.urandom(32)
    manager = KeyRotationManager(key1)

    encrypted1 = manager.encrypt(b"message 1")
    manager.rotate(os.urandom(32))
    encrypted2 = manager.encrypt(b"message 2")

    assert manager.decrypt(encrypted1) == b"message 1"
    assert manager.decrypt(encrypted2) == b"message 2"

    print("✓ Key rotation")


def test_group_encryption():
    """Test group encryption example (new feature)."""
    from shield.group import GroupEncryption
    import os

    group = GroupEncryption()
    alice_key = os.urandom(32)
    bob_key = os.urandom(32)

    group.add_member("alice", alice_key)
    group.add_member("bob", bob_key)

    encrypted = group.encrypt(b"group message")
    assert GroupEncryption.decrypt(encrypted, "alice", alice_key) == b"group message"
    assert GroupEncryption.decrypt(encrypted, "bob", bob_key) == b"group message"

    print("✓ Group encryption")


def test_identity_provider():
    """Test identity provider example (new feature)."""
    from shield.identity import IdentityProvider
    import os

    provider = IdentityProvider(os.urandom(32))
    identity = provider.register("alice", "password123", "Alice Smith")

    token = provider.authenticate("alice", "password123")
    assert token is not None

    session = provider.validate_token(token)
    assert session.user_id == "alice"

    print("✓ Identity provider (SSO)")


def main():
    print("CHEATSHEET.md Example Tests")
    print("=" * 40)

    test_basic_encryption()
    test_preshared_key()
    test_streaming()
    test_forward_secrecy()
    test_totp()
    test_recovery_codes()

    # New features
    print("\n--- New Features ---")
    test_signatures()
    test_key_exchange()
    test_key_rotation()
    test_group_encryption()
    test_identity_provider()

    print("\n" + "=" * 40)
    print("All CHEATSHEET examples work!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
