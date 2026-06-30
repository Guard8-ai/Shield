"""Tests for the post-quantum hybrid key exchange (shield.pqhybrid)."""

import pytest

from shield import Shield
from shield.pqhybrid import (
    HybridPrivateKey,
    HybridPublicKey,
    initiate,
    PUBLIC_BUNDLE_SIZE,
    HANDSHAKE_SIZE,
)


def _mlkem_available() -> bool:
    """ML-KEM-768 needs a cryptography/OpenSSL backend that supports it
    (OpenSSL >= 3.5). On older backends (e.g. Python 3.8 wheels) it raises
    UnsupportedAlgorithm; skip the post-quantum suite there rather than fail."""
    try:
        HybridPrivateKey.generate()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _mlkem_available(),
    reason="ML-KEM-768 not supported by this cryptography/OpenSSL backend",
)


def test_both_sides_derive_the_same_key():
    bob = HybridPrivateKey.generate()
    handshake, alice_key = initiate(bob.public_key())
    bob_key = bob.accept(handshake)
    assert alice_key == bob_key
    assert len(alice_key) == 32


def test_end_to_end_message_with_shield():
    """The whole point: strangers exchange an encrypted message."""
    bob = HybridPrivateKey.generate()
    bob_public = bob.public_key().to_bytes()  # published

    # Alice
    handshake, alice_key = initiate(HybridPublicKey.from_bytes(bob_public))
    ciphertext = Shield.with_key(alice_key).encrypt(b"hello bob, this is quantum-safe")

    # Bob
    bob_key = bob.accept(handshake)
    plaintext = Shield.with_key(bob_key).decrypt(ciphertext)
    assert plaintext == b"hello bob, this is quantum-safe"


def test_each_handshake_is_unique():
    """Ephemeral exchange: same recipient, different key every time."""
    bob = HybridPrivateKey.generate()
    h1, k1 = initiate(bob.public_key())
    h2, k2 = initiate(bob.public_key())
    assert h1 != h2
    # Fresh ephemeral + fresh encapsulation each time => a unique session key per
    # exchange. NOTE: this is uniqueness, NOT forward secrecy — the recipient's
    # key is static, so compromise of it exposes recorded sessions (see module docs).
    assert k1 != k2


def test_wrong_recipient_cannot_derive_key():
    bob = HybridPrivateKey.generate()
    mallory = HybridPrivateKey.generate()
    handshake, alice_key = initiate(bob.public_key())
    # Mallory's handshake is sized correctly but decapsulates to a different secret.
    mallory_key = mallory.accept(handshake)
    assert mallory_key != alice_key


def test_tampered_handshake_breaks_decryption():
    bob = HybridPrivateKey.generate()
    handshake, alice_key = initiate(bob.public_key())
    ciphertext = Shield.with_key(alice_key).encrypt(b"secret")

    tampered = bytearray(handshake)
    tampered[0] ^= 0xFF  # flip a bit in the ephemeral public key
    bob_key = bob.accept(bytes(tampered))
    assert bob_key != alice_key
    # A mismatched key fails authentication in Shield (returns None).
    assert Shield.with_key(bob_key).decrypt(ciphertext) is None


def test_public_key_serialization_roundtrip():
    bob = HybridPrivateKey.generate()
    pub = bob.public_key()
    data = pub.to_bytes()
    assert len(data) == PUBLIC_BUNDLE_SIZE
    restored = HybridPublicKey.from_bytes(data)
    assert restored.to_bytes() == data
    # The restored key still works for a full exchange.
    handshake, alice_key = initiate(restored)
    assert bob.accept(handshake) == alice_key


def test_handshake_has_expected_size():
    bob = HybridPrivateKey.generate()
    handshake, _ = initiate(bob.public_key())
    assert len(handshake) == HANDSHAKE_SIZE


@pytest.mark.parametrize("bad", [b"", b"too-short", b"\x00" * (PUBLIC_BUNDLE_SIZE - 1)])
def test_bad_public_bundle_rejected(bad):
    with pytest.raises(ValueError):
        HybridPublicKey.from_bytes(bad)


def test_bad_handshake_size_rejected():
    bob = HybridPrivateKey.generate()
    with pytest.raises(ValueError):
        bob.accept(b"\x00" * (HANDSHAKE_SIZE - 1))
