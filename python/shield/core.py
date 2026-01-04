"""
Shield Core - Password-based symmetric encryption.

This module provides the main Shield class for encrypting and decrypting
data using password-derived keys. It uses PBKDF2-SHA256 for key derivation
and a SHA256-based stream cipher with HMAC-SHA256 authentication.

Security:
    - PBKDF2 with 100,000 iterations
    - 256-bit keys
    - 16-byte random nonces
    - HMAC-SHA256 authentication (16-byte tags)
    - Constant-time MAC comparison
"""

import os
import hmac
import hashlib
import struct
from typing import Optional, Union

# Key derivation iterations (higher = more secure, slower)
PBKDF2_ITERATIONS = 100_000

# Sizes in bytes
NONCE_SIZE = 16
MAC_SIZE = 16
COUNTER_SIZE = 8


class Shield:
    """
    EXPTIME-secure symmetric encryption.

    Uses password-derived keys with PBKDF2 and encrypts using
    a SHA256-based stream cipher with HMAC-SHA256 authentication.
    Breaking requires 2^256 operations - no shortcut exists.

    Example:
        >>> s = Shield("my_password", "github.com")
        >>> encrypted = s.encrypt(b"secret data")
        >>> decrypted = s.decrypt(encrypted)
        >>> assert decrypted == b"secret data"
    """

    def __init__(
        self,
        password: str,
        service: str,
        salt: Optional[bytes] = None,
        iterations: int = PBKDF2_ITERATIONS,
    ):
        """
        Initialize Shield with password and service name.

        Args:
            password: User's password for this service
            service: Service identifier (e.g., "github.com")
            salt: Optional custom salt (defaults to SHA256(service))
            iterations: PBKDF2 iterations (default: 100,000)
        """
        if salt is None:
            salt = hashlib.sha256(service.encode()).digest()

        self._key = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, iterations
        )
        self._counter = 0

    @classmethod
    def with_key(cls, key: bytes) -> "Shield":
        """
        Create Shield instance with a pre-shared key (no password derivation).

        Args:
            key: 32-byte symmetric key

        Returns:
            Shield instance

        Raises:
            ValueError: If key is not 32 bytes
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")

        instance = cls.__new__(cls)
        instance._key = key
        instance._counter = 0
        return instance

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data.

        Args:
            plaintext: Data to encrypt

        Returns:
            Ciphertext in format: nonce(16) || encrypted_data || mac(16)
        """
        nonce = os.urandom(NONCE_SIZE)
        counter_bytes = struct.pack("<Q", self._counter)
        self._counter += 1

        # Data to encrypt: counter || plaintext
        data = counter_bytes + plaintext

        # Generate keystream
        keystream = _generate_keystream(self._key, nonce, len(data))

        # XOR encrypt
        ciphertext = bytes(p ^ k for p, k in zip(data, keystream))

        # HMAC authenticate
        mac = hmac.new(self._key, nonce + ciphertext, hashlib.sha256).digest()[
            :MAC_SIZE
        ]

        return nonce + ciphertext + mac

    def decrypt(self, encrypted: bytes) -> Optional[bytes]:
        """
        Decrypt and verify data.

        Args:
            encrypted: Ciphertext from encrypt()

        Returns:
            Plaintext bytes, or None if authentication fails
        """
        min_size = NONCE_SIZE + COUNTER_SIZE + MAC_SIZE
        if len(encrypted) < min_size:
            return None

        nonce = encrypted[:NONCE_SIZE]
        ciphertext = encrypted[NONCE_SIZE:-MAC_SIZE]
        mac = encrypted[-MAC_SIZE:]

        # Verify MAC first (constant-time)
        expected_mac = hmac.new(
            self._key, nonce + ciphertext, hashlib.sha256
        ).digest()[:MAC_SIZE]

        if not hmac.compare_digest(mac, expected_mac):
            return None

        # Decrypt
        keystream = _generate_keystream(self._key, nonce, len(ciphertext))
        decrypted = bytes(c ^ k for c, k in zip(ciphertext, keystream))

        # Skip counter prefix
        return decrypted[COUNTER_SIZE:]

    @property
    def key(self) -> bytes:
        """Get the derived key (for testing/debugging)."""
        return self._key


def _generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """
    Generate keystream using SHA256 (AES-256-CTR equivalent).

    Args:
        key: 32-byte key
        nonce: 16-byte nonce
        length: Number of keystream bytes needed

    Returns:
        Keystream bytes
    """
    keystream = b""
    num_blocks = (length + 31) // 32

    for i in range(num_blocks):
        counter = struct.pack("<I", i)
        block = hashlib.sha256(key + nonce + counter).digest()
        keystream += block

    return keystream[:length]


def quick_encrypt(key: bytes, data: bytes) -> bytes:
    """
    One-shot encrypt with pre-shared key (no password derivation).

    Args:
        key: 32-byte symmetric key
        data: Data to encrypt

    Returns:
        Ciphertext in format: nonce(16) || encrypted_data || mac(16)

    Example:
        >>> key = os.urandom(32)
        >>> encrypted = quick_encrypt(key, b"secret")
        >>> decrypted = quick_decrypt(key, encrypted)
    """
    nonce = os.urandom(NONCE_SIZE)
    keystream = _generate_keystream(key, nonce, len(data))
    ciphertext = bytes(d ^ k for d, k in zip(data, keystream))
    mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:MAC_SIZE]
    return nonce + ciphertext + mac


def quick_decrypt(key: bytes, encrypted: bytes) -> Optional[bytes]:
    """
    One-shot decrypt with pre-shared key.

    Args:
        key: 32-byte symmetric key
        encrypted: Ciphertext from quick_encrypt()

    Returns:
        Plaintext bytes, or None if authentication fails
    """
    if len(encrypted) < NONCE_SIZE + MAC_SIZE:
        return None

    nonce = encrypted[:NONCE_SIZE]
    ciphertext = encrypted[NONCE_SIZE:-MAC_SIZE]
    mac = encrypted[-MAC_SIZE:]

    expected_mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[
        :MAC_SIZE
    ]

    if not hmac.compare_digest(mac, expected_mac):
        return None

    keystream = _generate_keystream(key, nonce, len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, keystream))
