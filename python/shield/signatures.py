"""
Shield Signatures - Digital signatures without public-key crypto.

Two signature types:
1. SymmetricSignature: HMAC-based, requires shared verification key
2. LamportSignature: One-time hash-chain signatures (post-quantum)

Example:
    >>> from shield.signatures import SymmetricSignature, LamportSignature
    >>>
    >>> # HMAC signatures (reusable)
    >>> signer = SymmetricSignature.generate()
    >>> sig = signer.sign(b"message")
    >>> signer.verify(b"message", sig, signer.verification_key)  # True
    >>>
    >>> # Lamport one-time signatures
    >>> lamport = LamportSignature.generate()
    >>> sig = lamport.sign(b"message")
    >>> LamportSignature.verify(b"message", sig, lamport.public_key)  # True
"""

import hmac
import hashlib
import struct
import time
import secrets
from typing import Optional, List, Tuple


class SymmetricSignature:
    """
    HMAC-based digital signatures.

    Uses a shared verification key model - the verification key
    must be distributed to verifiers through a secure channel.

    Includes timestamp for replay protection.
    """

    def __init__(self, signing_key: bytes):
        """
        Initialize with signing key.

        Args:
            signing_key: 32-byte secret signing key
        """
        self.signing_key = signing_key
        self.verification_key = hashlib.sha256(b'verify:' + signing_key).digest()

    @classmethod
    def generate(cls) -> 'SymmetricSignature':
        """Generate new signing identity."""
        return cls(secrets.token_bytes(32))

    @classmethod
    def from_password(cls, password: str, identity: str) -> 'SymmetricSignature':
        """
        Derive signing key from password and identity.

        Args:
            password: User's password
            identity: Identity string (e.g., email)

        Returns:
            SymmetricSignature instance
        """
        salt = hashlib.sha256(f"sign:{identity}".encode()).digest()
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return cls(key)

    def sign(self, message: bytes, include_timestamp: bool = True) -> bytes:
        """
        Sign a message.

        Args:
            message: Message to sign
            include_timestamp: Include timestamp for replay protection

        Returns:
            Signature bytes (40 bytes with timestamp, 32 without)
        """
        if include_timestamp:
            timestamp = struct.pack('<Q', int(time.time()))
            sig_data = timestamp + message
            signature = hmac.new(self.signing_key, sig_data, hashlib.sha256).digest()
            return timestamp + signature
        else:
            return hmac.new(self.signing_key, message, hashlib.sha256).digest()

    def verify(
        self,
        message: bytes,
        signature: bytes,
        verification_key: bytes,
        max_age: int = 300,
    ) -> bool:
        """
        Verify a signature.

        Args:
            message: Original message
            signature: Signature from sign()
            verification_key: Signer's verification key
            max_age: Maximum signature age in seconds (0 = no check)

        Returns:
            True if signature is valid
        """
        # Check if this is our own signature
        if not hmac.compare_digest(verification_key, self.verification_key):
            # Can only verify our own signatures in symmetric model
            # For cross-verification, need the actual signing key
            return False

        if len(signature) == 40:  # With timestamp
            timestamp = struct.unpack('<Q', signature[:8])[0]
            sig = signature[8:]

            if max_age > 0:
                now = int(time.time())
                if abs(now - timestamp) > max_age:
                    return False

            sig_data = signature[:8] + message
            expected = hmac.new(self.signing_key, sig_data, hashlib.sha256).digest()
        else:  # Without timestamp
            sig = signature
            expected = hmac.new(self.signing_key, message, hashlib.sha256).digest()

        return hmac.compare_digest(sig, expected)

    def get_fingerprint(self) -> str:
        """Get key fingerprint for identification."""
        return hashlib.sha256(self.verification_key).hexdigest()[:16]


class LamportSignature:
    """
    Lamport one-time signatures (post-quantum secure).

    Each key pair can only sign ONE message. After signing,
    the private key should be discarded.

    Public verification - anyone with the public key can verify.

    Warning: Signing multiple messages with the same key compromises security!
    """

    BITS = 256  # Hash output size

    def __init__(self, private_key: Optional[List[Tuple[bytes, bytes]]] = None):
        """
        Initialize with private key or generate new.

        Args:
            private_key: List of (chain_0, chain_1) tuples, or None to generate
        """
        if private_key is None:
            private_key = self._generate_private_key()

        self._private_key = private_key
        self._used = False
        self.public_key = self._compute_public_key()

    @classmethod
    def generate(cls) -> 'LamportSignature':
        """Generate new Lamport key pair."""
        return cls()

    def _generate_private_key(self) -> List[Tuple[bytes, bytes]]:
        """Generate private key (random chain starts)."""
        return [
            (secrets.token_bytes(32), secrets.token_bytes(32))
            for _ in range(self.BITS)
        ]

    def _hash(self, data: bytes) -> bytes:
        """Single hash operation."""
        return hashlib.sha256(data).digest()

    def _compute_public_key(self) -> bytes:
        """Compute public key from private key."""
        parts = []
        for chain_0, chain_1 in self._private_key:
            parts.append(self._hash(chain_0))
            parts.append(self._hash(chain_1))
        return b''.join(parts)

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message (ONE TIME ONLY).

        Args:
            message: Message to sign

        Returns:
            Signature bytes (256 * 32 = 8192 bytes)

        Raises:
            RuntimeError: If key has already been used
        """
        if self._used:
            raise RuntimeError("Lamport key already used - generate new key pair")

        self._used = True
        msg_hash = hashlib.sha256(message).digest()

        signature_parts = []
        for i in range(self.BITS):
            byte_idx = i // 8
            bit_idx = i % 8
            bit = (msg_hash[byte_idx] >> bit_idx) & 1

            chain_0, chain_1 = self._private_key[i]
            signature_parts.append(chain_1 if bit else chain_0)

        return b''.join(signature_parts)

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a Lamport signature.

        Args:
            message: Original message
            signature: Signature from sign()
            public_key: Signer's public key

        Returns:
            True if signature is valid
        """
        if len(signature) != 256 * 32:
            return False
        if len(public_key) != 256 * 64:
            return False

        msg_hash = hashlib.sha256(message).digest()

        for i in range(256):
            byte_idx = i // 8
            bit_idx = i % 8
            bit = (msg_hash[byte_idx] >> bit_idx) & 1

            revealed = signature[i * 32:(i + 1) * 32]
            hashed = hashlib.sha256(revealed).digest()

            # Check against correct public key component
            if bit:
                expected = public_key[i * 64 + 32:i * 64 + 64]
            else:
                expected = public_key[i * 64:i * 64 + 32]

            if hashed != expected:
                return False

        return True

    @property
    def is_used(self) -> bool:
        """Check if this key has been used."""
        return self._used

    def get_fingerprint(self) -> str:
        """Get public key fingerprint."""
        return hashlib.sha256(self.public_key).hexdigest()[:16]
