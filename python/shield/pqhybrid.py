"""
Shield Post-Quantum Hybrid Key Exchange.

This solves the one thing Shield's password / pre-shared-key modes can't: letting
two parties who have **never shared a secret** agree on a 32-byte key over an open,
eavesdropped network — and staying safe even against an attacker who records the
traffic today and owns a quantum computer years from now ("harvest now, decrypt
later").

It is a *hybrid* exchange: it runs two independent key exchanges and mixes both
results, so an attacker must break **both** to win:

  * X25519   — classical elliptic-curve Diffie-Hellman (battle-tested today).
  * ML-KEM-768 — NIST FIPS 203 lattice KEM (quantum-resistant), aka CRYSTALS-Kyber.

Both primitives come from the audited `cryptography` package (OpenSSL), not from
hand-rolled math.

Mental model (padlock analogy):
    Bob publishes an open "padlock" (his public key). Alice locks a fresh secret
    inside it and ships the locked box to Bob. Only Bob's private key opens it, so
    only Alice and Bob learn the secret. ML-KEM's padlock resists quantum attacks;
    we chain it with the classical X25519 padlock for belt-and-suspenders safety.

Security properties — and limits (stated honestly):
  * Confidential against a passive eavesdropper who does NOT hold the recipient's
    private key, including a future quantum computer. This is the "harvest now,
    decrypt later" guarantee — it holds *only* for an attacker without the key.
  * Authenticated TO the recipient: the shared key is bound (through the KDF
    transcript) to the recipient's exact public key and to this specific
    handshake, so a captured handshake cannot be re-pointed at a different
    recipient (no unknown-key-share).
  * Anonymous sender: the sender is NOT authenticated. If you must know who sent
    a message, sign it (shield.signatures) or run it over an authenticated channel.
  * NO forward secrecy against compromise of the recipient's LONG-TERM key. The
    recipient's ML-KEM and X25519 keys are static, so if that private key is ever
    stolen, an attacker who recorded past handshakes can recompute those session
    keys. For full forward secrecy (past messages stay safe even if a long-term
    key later leaks), use an interactive ratchet (shield.ratchet.RatchetSession),
    not this one-shot exchange. Rotate the recipient keypair periodically to bound
    exposure.

Typical use:

    >>> from shield.pqhybrid import HybridPrivateKey, initiate
    >>> from shield import Shield
    >>>
    >>> # --- Bob, once: publish his public key ("quantum-safe address") ---
    >>> bob = HybridPrivateKey.generate()
    >>> bob_public_bytes = bob.public_key().to_bytes()   # share this freely
    >>>
    >>> # --- Alice: derive a shared key and send an encrypted message ---
    >>> from shield.pqhybrid import HybridPublicKey
    >>> handshake, shared_key = initiate(HybridPublicKey.from_bytes(bob_public_bytes))
    >>> ciphertext = Shield.with_key(shared_key).encrypt(b"hello bob")
    >>> # Alice sends Bob: handshake + ciphertext
    >>>
    >>> # --- Bob: recover the same shared key and decrypt ---
    >>> shared_key_bob = bob.accept(handshake)
    >>> assert shared_key_bob == shared_key
    >>> Shield.with_key(shared_key_bob).decrypt(ciphertext)
    b'hello bob'
"""

from __future__ import annotations

from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ML-KEM-768 = NIST security level 3 (~AES-192). The common, recommended default:
# stronger than 512, much cheaper than 1024.
_MLKEM_PUBLIC_SIZE = 1184   # bytes of an ML-KEM-768 public key
_MLKEM_CIPHERTEXT_SIZE = 1088  # bytes of an ML-KEM-768 encapsulation ciphertext
_MLKEM_SEED_SIZE = 64       # portable FIPS 203 seed (d || z)
_X25519_PUBLIC_SIZE = 32
_X25519_PRIVATE_SIZE = 32
_SHARED_KEY_SIZE = 32       # output: a Shield pre-shared key

# A public bundle is the two public keys concatenated; a handshake is the sender's
# ephemeral X25519 public key followed by the ML-KEM ciphertext.
PUBLIC_BUNDLE_SIZE = _MLKEM_PUBLIC_SIZE + _X25519_PUBLIC_SIZE      # 1216
HANDSHAKE_SIZE = _X25519_PUBLIC_SIZE + _MLKEM_CIPHERTEXT_SIZE      # 1120

# Domain-separation label for the KDF, versioned so a future construction can't be
# confused with this one.
_KDF_SALT = b"shield/pq-hybrid/v1"


def _derive_shared_key(
    classical_secret: bytes,
    pq_secret: bytes,
    transcript: bytes,
) -> bytes:
    """Mix the two exchange results into one 32-byte key.

    Concatenating the secrets and running them through HKDF binds the result to
    BOTH exchanges (hybrid security) and to the full transcript (the public keys
    and ciphertext), which prevents an attacker from substituting their own keys.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_SHARED_KEY_SIZE,
        salt=_KDF_SALT,
        info=transcript,
    ).derive(classical_secret + pq_secret)


class HybridPublicKey:
    """A recipient's public "address": an ML-KEM public key + an X25519 public key.

    Safe to publish anywhere. A sender uses it to derive a shared key with
    ``initiate()``.
    """

    __slots__ = ("mlkem_public_bytes", "x25519_public_bytes")

    def __init__(self, mlkem_public_bytes: bytes, x25519_public_bytes: bytes):
        if len(mlkem_public_bytes) != _MLKEM_PUBLIC_SIZE:
            raise ValueError(
                f"ML-KEM public key must be {_MLKEM_PUBLIC_SIZE} bytes, "
                f"got {len(mlkem_public_bytes)}"
            )
        if len(x25519_public_bytes) != _X25519_PUBLIC_SIZE:
            raise ValueError(
                f"X25519 public key must be {_X25519_PUBLIC_SIZE} bytes, "
                f"got {len(x25519_public_bytes)}"
            )
        self.mlkem_public_bytes = mlkem_public_bytes
        self.x25519_public_bytes = x25519_public_bytes

    def to_bytes(self) -> bytes:
        """Serialize for publishing/transport (1216 bytes)."""
        return self.mlkem_public_bytes + self.x25519_public_bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "HybridPublicKey":
        if len(data) != PUBLIC_BUNDLE_SIZE:
            raise ValueError(
                f"Public bundle must be {PUBLIC_BUNDLE_SIZE} bytes, got {len(data)}"
            )
        return cls(data[:_MLKEM_PUBLIC_SIZE], data[_MLKEM_PUBLIC_SIZE:])


class HybridPrivateKey:
    """A recipient's private key. Generate once, keep secret, publish the public key.

    Use ``accept(handshake)`` to recover the shared key a sender produced with
    ``initiate(public_key)``.
    """

    __slots__ = ("_mlkem_private", "_x25519_private")

    def __init__(
        self,
        mlkem_private: mlkem.MLKEM768PrivateKey,
        x25519_private: x25519.X25519PrivateKey,
    ):
        self._mlkem_private = mlkem_private
        self._x25519_private = x25519_private

    @classmethod
    def generate(cls) -> "HybridPrivateKey":
        """Create a fresh keypair using the system CSPRNG."""
        return cls(
            mlkem.MLKEM768PrivateKey.generate(),
            x25519.X25519PrivateKey.generate(),
        )

    def to_bytes(self) -> bytes:
        """Serialize the PRIVATE key for secure storage (96 bytes).

        Layout: ML-KEM-768 64-byte seed || X25519 32-byte scalar. The ML-KEM seed
        is the portable FIPS 203 form (d || z) that every conforming library can
        re-expand, which is what makes a stored key usable across languages.

        Keep this secret — anyone holding it can decrypt messages sent to you.
        """
        return (
            self._mlkem_private.private_bytes_raw()
            + self._x25519_private.private_bytes_raw()
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "HybridPrivateKey":
        """Restore a keypair previously produced by ``to_bytes()``."""
        if len(data) != _MLKEM_SEED_SIZE + _X25519_PRIVATE_SIZE:
            raise ValueError(
                f"Private key must be "
                f"{_MLKEM_SEED_SIZE + _X25519_PRIVATE_SIZE} bytes, got {len(data)}"
            )
        mlkem_seed = data[:_MLKEM_SEED_SIZE]
        x25519_scalar = data[_MLKEM_SEED_SIZE:]
        return cls(
            mlkem.MLKEM768PrivateKey.from_seed_bytes(mlkem_seed),
            x25519.X25519PrivateKey.from_private_bytes(x25519_scalar),
        )

    def public_key(self) -> HybridPublicKey:
        """The publishable public half of this keypair."""
        return HybridPublicKey(
            self._mlkem_private.public_key().public_bytes_raw(),
            self._x25519_private.public_key().public_bytes_raw(),
        )

    def accept(self, handshake: bytes) -> bytes:
        """Recipient side: turn a sender's handshake into the shared 32-byte key.

        Args:
            handshake: the ``HANDSHAKE_SIZE``-byte blob produced by ``initiate()``.

        Returns:
            The 32-byte shared key (feed it to ``Shield.with_key``).
        """
        if len(handshake) != HANDSHAKE_SIZE:
            raise ValueError(
                f"Handshake must be {HANDSHAKE_SIZE} bytes, got {len(handshake)}"
            )
        eph_x25519_public_bytes = handshake[:_X25519_PUBLIC_SIZE]
        kem_ciphertext = handshake[_X25519_PUBLIC_SIZE:]

        # ML-KEM: open the padlock to recover the post-quantum secret.
        pq_secret = self._mlkem_private.decapsulate(kem_ciphertext)

        # X25519: classical Diffie-Hellman with the sender's ephemeral public key.
        eph_public = x25519.X25519PublicKey.from_public_bytes(eph_x25519_public_bytes)
        classical_secret = self._x25519_private.exchange(eph_public)

        my_public = self.public_key()
        transcript = (
            my_public.to_bytes() + eph_x25519_public_bytes + kem_ciphertext
        )
        return _derive_shared_key(classical_secret, pq_secret, transcript)


def initiate(peer_public: HybridPublicKey) -> Tuple[bytes, bytes]:
    """Sender side: derive a shared key for ``peer_public`` and the handshake to send.

    Args:
        peer_public: the recipient's published ``HybridPublicKey``.

    Returns:
        ``(handshake, shared_key)`` — transmit ``handshake`` to the recipient (who
        passes it to ``accept()``); use ``shared_key`` with ``Shield.with_key``.
    """
    # ML-KEM: lock a fresh secret inside the recipient's public padlock.
    peer_mlkem_public = mlkem.MLKEM768PublicKey.from_public_bytes(
        peer_public.mlkem_public_bytes
    )
    pq_secret, kem_ciphertext = peer_mlkem_public.encapsulate()

    # X25519: a one-time ("ephemeral") classical exchange against the peer's key.
    eph_private = x25519.X25519PrivateKey.generate()
    eph_x25519_public_bytes = eph_private.public_key().public_bytes_raw()
    peer_x25519_public = x25519.X25519PublicKey.from_public_bytes(
        peer_public.x25519_public_bytes
    )
    classical_secret = eph_private.exchange(peer_x25519_public)

    transcript = (
        peer_public.to_bytes() + eph_x25519_public_bytes + kem_ciphertext
    )
    shared_key = _derive_shared_key(classical_secret, pq_secret, transcript)
    handshake = eph_x25519_public_bytes + kem_ciphertext
    return handshake, shared_key
