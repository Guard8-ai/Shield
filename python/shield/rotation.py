"""
Shield Key Rotation - Version-based key management.

Supports seamless key rotation without breaking existing encrypted data.
Each ciphertext is tagged with the key version used.

Example:
    >>> from shield.rotation import KeyRotationManager
    >>>
    >>> manager = KeyRotationManager(initial_key, version=1)
    >>> encrypted = manager.encrypt(b"secret")
    >>>
    >>> # Rotate to new key
    >>> manager.rotate(new_key)
    >>>
    >>> # Old data still decrypts
    >>> decrypted = manager.decrypt(encrypted)  # Uses version 1 key
"""

import os
import hmac
import hashlib
import struct
from typing import Dict, Optional, Tuple


def _generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate keystream using SHA256."""
    keystream = b""
    for i in range((length + 31) // 32):
        keystream += hashlib.sha256(key + nonce + struct.pack("<I", i)).digest()
    return keystream[:length]


class KeyRotationManager:
    """
    Manages multiple key versions for seamless rotation.

    Ciphertext format: version(4) || nonce(16) || ciphertext || mac(16)
    """

    def __init__(self, key: bytes, version: int = 1):
        """
        Initialize with current key.

        Args:
            key: 32-byte encryption key
            version: Key version number
        """
        self._keys: Dict[int, bytes] = {version: key}
        self._current_version = version

    @property
    def current_version(self) -> int:
        """Get current key version."""
        return self._current_version

    @property
    def versions(self) -> list:
        """Get all available key versions."""
        return sorted(self._keys.keys())

    def add_key(self, key: bytes, version: int) -> None:
        """
        Add historical key for decryption.

        Args:
            key: 32-byte key
            version: Key version number
        """
        if version in self._keys:
            raise ValueError(f"Version {version} already exists")
        self._keys[version] = key

    def rotate(self, new_key: bytes, new_version: Optional[int] = None) -> int:
        """
        Rotate to new key.

        Args:
            new_key: New 32-byte key
            new_version: Version number (default: current + 1)

        Returns:
            New version number
        """
        if new_version is None:
            new_version = self._current_version + 1

        if new_version <= self._current_version:
            raise ValueError("New version must be greater than current")

        self._keys[new_version] = new_key
        self._current_version = new_version
        return new_version

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt with current key (includes version tag).

        Args:
            plaintext: Data to encrypt

        Returns:
            Versioned ciphertext
        """
        key = self._keys[self._current_version]
        nonce = os.urandom(16)

        # Generate keystream and encrypt
        keystream = _generate_keystream(key, nonce, len(plaintext))
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))

        # HMAC authenticate (includes version)
        version_bytes = struct.pack("<I", self._current_version)
        mac = hmac.new(
            key,
            version_bytes + nonce + ciphertext,
            hashlib.sha256
        ).digest()[:16]

        return version_bytes + nonce + ciphertext + mac

    def decrypt(self, encrypted: bytes) -> bytes:
        """
        Decrypt with appropriate key version.

        Args:
            encrypted: Versioned ciphertext from encrypt()

        Returns:
            Plaintext

        Raises:
            ValueError: If version unknown or authentication fails
        """
        if len(encrypted) < 36:  # 4 version + 16 nonce + 16 mac minimum
            raise ValueError("Ciphertext too short")

        version = struct.unpack("<I", encrypted[:4])[0]
        nonce = encrypted[4:20]
        ciphertext = encrypted[20:-16]
        mac = encrypted[-16:]

        if version not in self._keys:
            raise ValueError(f"Unknown key version: {version}")

        key = self._keys[version]

        # Verify MAC
        expected_mac = hmac.new(
            key,
            encrypted[:-16],
            hashlib.sha256
        ).digest()[:16]

        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("Authentication failed")

        # Decrypt
        keystream = _generate_keystream(key, nonce, len(ciphertext))
        return bytes(c ^ k for c, k in zip(ciphertext, keystream))

    def prune_old_keys(self, keep_versions: int = 2) -> list:
        """
        Remove old keys, keeping only recent versions.

        Args:
            keep_versions: Number of versions to keep

        Returns:
            List of pruned version numbers
        """
        if keep_versions < 1:
            raise ValueError("Must keep at least 1 version")

        versions = sorted(self._keys.keys(), reverse=True)
        to_keep = set(versions[:keep_versions])

        # Always keep current version
        to_keep.add(self._current_version)

        pruned = []
        for v in list(self._keys.keys()):
            if v not in to_keep:
                del self._keys[v]
                pruned.append(v)

        return pruned

    def re_encrypt(self, encrypted: bytes) -> bytes:
        """
        Re-encrypt data with current key.

        Useful for migrating old data to new key version.

        Args:
            encrypted: Old versioned ciphertext

        Returns:
            New ciphertext encrypted with current key
        """
        plaintext = self.decrypt(encrypted)
        return self.encrypt(plaintext)

    def export_keys(self) -> Dict[int, bytes]:
        """Export all keys (for backup)."""
        return dict(self._keys)

    @classmethod
    def import_keys(cls, keys: Dict[int, bytes], current_version: int = None) -> 'KeyRotationManager':
        """
        Import keys from backup.

        Args:
            keys: Dictionary of version -> key
            current_version: Current version (default: highest)

        Returns:
            KeyRotationManager instance
        """
        if not keys:
            raise ValueError("No keys provided")

        if current_version is None:
            current_version = max(keys.keys())

        first_version = min(keys.keys())
        manager = cls(keys[first_version], first_version)

        for version, key in keys.items():
            if version != first_version:
                manager._keys[version] = key

        manager._current_version = current_version
        return manager
