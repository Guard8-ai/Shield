"""Tests for Shield key rotation."""

import os
import pytest
from shield.rotation import KeyRotationManager


class TestKeyRotationManager:
    """Test KeyRotationManager class."""

    def test_encrypt_decrypt(self):
        """Basic encrypt/decrypt."""
        key = os.urandom(32)
        manager = KeyRotationManager(key, version=1)
        plaintext = b"secret data"
        encrypted = manager.encrypt(plaintext)
        decrypted = manager.decrypt(encrypted)
        assert decrypted == plaintext

    def test_version_in_ciphertext(self):
        """Ciphertext includes version."""
        key = os.urandom(32)
        manager = KeyRotationManager(key, version=5)
        encrypted = manager.encrypt(b"test")
        # Version is first 4 bytes
        import struct
        version = struct.unpack("<I", encrypted[:4])[0]
        assert version == 5

    def test_rotate_key(self):
        """Key rotation works."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        manager = KeyRotationManager(key1, version=1)

        # Encrypt with version 1
        enc1 = manager.encrypt(b"message 1")

        # Rotate to version 2
        manager.rotate(key2)
        assert manager.current_version == 2

        # Encrypt with version 2
        enc2 = manager.encrypt(b"message 2")

        # Both decrypt correctly
        assert manager.decrypt(enc1) == b"message 1"
        assert manager.decrypt(enc2) == b"message 2"

    def test_unknown_version_fails(self):
        """Unknown version raises error."""
        manager = KeyRotationManager(os.urandom(32), version=1)
        encrypted = manager.encrypt(b"test")

        # Modify version to unknown
        import struct
        bad_version = struct.pack("<I", 999) + encrypted[4:]

        with pytest.raises(ValueError, match="Unknown key version"):
            manager.decrypt(bad_version)

    def test_tampered_ciphertext_fails(self):
        """Tampered ciphertext raises error."""
        manager = KeyRotationManager(os.urandom(32))
        encrypted = bytearray(manager.encrypt(b"test"))
        encrypted[25] ^= 0xFF

        with pytest.raises(ValueError, match="Authentication failed"):
            manager.decrypt(bytes(encrypted))

    def test_add_historical_key(self):
        """Add historical key for decryption."""
        old_key = os.urandom(32)
        new_key = os.urandom(32)

        # Create with old key, encrypt something
        old_manager = KeyRotationManager(old_key, version=1)
        old_encrypted = old_manager.encrypt(b"old data")

        # Create new manager without old key
        new_manager = KeyRotationManager(new_key, version=2)

        # Can't decrypt old data yet
        with pytest.raises(ValueError):
            new_manager.decrypt(old_encrypted)

        # Add old key
        new_manager.add_key(old_key, version=1)

        # Now can decrypt
        assert new_manager.decrypt(old_encrypted) == b"old data"

    def test_prune_old_keys(self):
        """Prune old keys."""
        manager = KeyRotationManager(os.urandom(32), version=1)

        # Add several versions
        for i in range(2, 6):
            manager.rotate(os.urandom(32), i)

        assert manager.versions == [1, 2, 3, 4, 5]

        # Prune to keep only 2 versions
        pruned = manager.prune_old_keys(keep_versions=2)

        assert set(pruned) == {1, 2, 3}
        assert manager.versions == [4, 5]

    def test_re_encrypt(self):
        """Re-encrypt with current key."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        manager = KeyRotationManager(key1, version=1)

        # Encrypt with v1
        enc1 = manager.encrypt(b"data")
        manager.rotate(key2)

        # Re-encrypt with v2
        enc2 = manager.re_encrypt(enc1)

        import struct
        v1 = struct.unpack("<I", enc1[:4])[0]
        v2 = struct.unpack("<I", enc2[:4])[0]

        assert v1 == 1
        assert v2 == 2
        assert manager.decrypt(enc2) == b"data"

    def test_export_import(self):
        """Export and import keys."""
        manager = KeyRotationManager(os.urandom(32), version=1)
        manager.rotate(os.urandom(32))
        manager.rotate(os.urandom(32))

        enc1 = manager.encrypt(b"test 1")
        enc3 = manager.encrypt(b"test 3")

        # Export
        exported = manager.export_keys()

        # Import to new manager
        new_manager = KeyRotationManager.import_keys(exported, current_version=3)

        assert new_manager.decrypt(enc1) == b"test 1"
        assert new_manager.decrypt(enc3) == b"test 3"
        assert new_manager.current_version == 3
