"""Tests for Shield core encryption."""

import os
import pytest
from shield.core import Shield, quick_encrypt, quick_decrypt


class TestShield:
    """Test Shield class."""

    def test_encrypt_decrypt(self):
        """Basic encrypt/decrypt cycle."""
        s = Shield("password", "test.service")
        plaintext = b"Hello, World!"
        encrypted = s.encrypt(plaintext)
        decrypted = s.decrypt(encrypted)
        assert decrypted == plaintext

    def test_different_passwords(self):
        """Different passwords produce different ciphertext."""
        s1 = Shield("password1", "service")
        s2 = Shield("password2", "service")
        plaintext = b"secret"
        enc1 = s1.encrypt(plaintext)
        enc2 = s2.encrypt(plaintext)
        assert enc1 != enc2

    def test_wrong_password_fails(self):
        """Wrong password returns None."""
        s1 = Shield("correct", "service")
        s2 = Shield("wrong", "service")
        plaintext = b"secret"
        encrypted = s1.encrypt(plaintext)
        decrypted = s2.decrypt(encrypted)
        assert decrypted is None

    def test_tampered_ciphertext_fails(self):
        """Tampered ciphertext returns None."""
        s = Shield("password", "service")
        encrypted = s.encrypt(b"secret")
        # Tamper with ciphertext
        tampered = encrypted[:20] + bytes([encrypted[20] ^ 0xFF]) + encrypted[21:]
        decrypted = s.decrypt(tampered)
        assert decrypted is None

    def test_empty_plaintext(self):
        """Empty plaintext works."""
        s = Shield("password", "service")
        encrypted = s.encrypt(b"")
        decrypted = s.decrypt(encrypted)
        assert decrypted == b""

    def test_large_plaintext(self):
        """Large plaintext works."""
        s = Shield("password", "service")
        plaintext = os.urandom(1024 * 1024)  # 1MB
        encrypted = s.encrypt(plaintext)
        decrypted = s.decrypt(encrypted)
        assert decrypted == plaintext

    def test_with_key(self):
        """Shield.with_key creates instance from raw key."""
        key = os.urandom(32)
        s = Shield.with_key(key)
        plaintext = b"test"
        encrypted = s.encrypt(plaintext)
        decrypted = s.decrypt(encrypted)
        assert decrypted == plaintext

    def test_with_key_invalid_length(self):
        """Shield.with_key rejects invalid key lengths."""
        with pytest.raises(ValueError):
            Shield.with_key(b"short")

    def test_key_derivation_deterministic(self):
        """Same password/service produces same key."""
        s1 = Shield("password", "service")
        s2 = Shield("password", "service")
        assert s1.key == s2.key

    def test_different_services_different_keys(self):
        """Different services produce different keys."""
        s1 = Shield("password", "service1")
        s2 = Shield("password", "service2")
        assert s1.key != s2.key

    def test_v2_roundtrip(self):
        """v2 format: basic encrypt/decrypt with replay protection."""
        s = Shield("password", "service", max_age_ms=60_000)
        plaintext = b"Test v2 message"
        encrypted = s.encrypt(plaintext)
        decrypted = s.decrypt(encrypted)
        assert decrypted == plaintext

    def test_v2_replay_protection_fresh(self):
        """v2 format: fresh message should decrypt successfully."""
        s = Shield("password", "service", max_age_ms=60_000)
        plaintext = b"Fresh message"
        encrypted = s.encrypt(plaintext)
        # Decrypt immediately - should succeed
        decrypted = s.decrypt(encrypted)
        assert decrypted == plaintext

    def test_v2_replay_protection_expired(self):
        """v2 format: expired message should be rejected."""
        import time
        import struct
        from shield.core import NONCE_SIZE, MAC_SIZE, V2_HEADER_SIZE

        s = Shield("password", "service", max_age_ms=1000)  # 1 second max age
        plaintext = b"Old message"

        # Manually create an old timestamp (2 seconds ago)
        old_timestamp_ms = int(time.time() * 1000) - 2000

        # Encrypt manually with old timestamp
        nonce = os.urandom(NONCE_SIZE)
        counter_bytes = struct.pack("<Q", 0)
        timestamp_bytes = struct.pack("<Q", old_timestamp_ms)
        pad_len = 32
        pad_len_byte = struct.pack("B", pad_len)
        padding = os.urandom(pad_len)

        data = counter_bytes + timestamp_bytes + pad_len_byte + padding + plaintext

        # Use internal encryption
        from shield.core import _generate_keystream
        import hmac
        import hashlib
        from shield.core import MAC_SIZE as MAC_SIZE_CONST

        keystream = _generate_keystream(s.key, nonce, len(data))
        ciphertext = bytes(p ^ k for p, k in zip(data, keystream))
        mac = hmac.new(s.key, nonce + ciphertext, hashlib.sha256).digest()[:MAC_SIZE_CONST]
        encrypted = nonce + ciphertext + mac

        # Should reject expired message
        decrypted = s.decrypt(encrypted)
        assert decrypted is None

    def test_v2_length_variation(self):
        """v2 format: multiple encryptions have different lengths (random padding)."""
        s = Shield("password", "service")
        plaintext = b"Same message"

        lengths = set()
        for _ in range(10):
            encrypted = s.encrypt(plaintext)
            lengths.add(len(encrypted))

        # Should have multiple different lengths due to random padding (32-128)
        assert len(lengths) > 1

    def test_v1_backward_compatibility(self):
        """Can decrypt v1 ciphertext (auto-detection)."""
        import struct
        from shield.core import NONCE_SIZE, MAC_SIZE, _generate_keystream
        import hmac
        import hashlib

        s = Shield("password", "service")
        plaintext = b"v1 message"

        # Manually create v1 ciphertext: counter(8) || plaintext
        nonce = os.urandom(NONCE_SIZE)
        counter_bytes = struct.pack("<Q", 0)
        data = counter_bytes + plaintext

        keystream = _generate_keystream(s.key, nonce, len(data))
        ciphertext = bytes(p ^ k for p, k in zip(data, keystream))
        mac = hmac.new(s.key, nonce + ciphertext, hashlib.sha256).digest()[:MAC_SIZE]
        encrypted = nonce + ciphertext + mac

        # Should auto-detect and decrypt as v1
        decrypted = s.decrypt(encrypted)
        assert decrypted == plaintext

    def test_decrypt_v1_explicit(self):
        """Explicit v1 decryption using decrypt_v1()."""
        import struct
        from shield.core import NONCE_SIZE, MAC_SIZE, _generate_keystream
        import hmac
        import hashlib

        s = Shield("password", "service")
        plaintext = b"v1 explicit"

        # Create v1 ciphertext
        nonce = os.urandom(NONCE_SIZE)
        counter_bytes = struct.pack("<Q", 0)
        data = counter_bytes + plaintext

        keystream = _generate_keystream(s.key, nonce, len(data))
        ciphertext = bytes(p ^ k for p, k in zip(data, keystream))
        mac = hmac.new(s.key, nonce + ciphertext, hashlib.sha256).digest()[:MAC_SIZE]
        encrypted = nonce + ciphertext + mac

        # Decrypt using explicit v1 method
        decrypted = s.decrypt_v1(encrypted)
        assert decrypted == plaintext

    def test_no_fallback_on_expired_v2(self):
        """Expired v2 message should NOT fallback to v1."""
        import time
        import struct
        from shield.core import NONCE_SIZE, MAC_SIZE, V2_HEADER_SIZE, _generate_keystream
        import hmac
        import hashlib

        s = Shield("password", "service", max_age_ms=500)

        # Create expired v2 message (2 seconds old)
        old_timestamp_ms = int(time.time() * 1000) - 2000
        plaintext = b"expired v2"

        nonce = os.urandom(NONCE_SIZE)
        counter_bytes = struct.pack("<Q", 0)
        timestamp_bytes = struct.pack("<Q", old_timestamp_ms)
        pad_len = 32
        pad_len_byte = struct.pack("B", pad_len)
        padding = os.urandom(pad_len)

        data = counter_bytes + timestamp_bytes + pad_len_byte + padding + plaintext

        keystream = _generate_keystream(s.key, nonce, len(data))
        ciphertext = bytes(p ^ k for p, k in zip(data, keystream))
        mac = hmac.new(s.key, nonce + ciphertext, hashlib.sha256).digest()[:MAC_SIZE]
        encrypted = nonce + ciphertext + mac

        # Should reject (not fallback to v1)
        decrypted = s.decrypt(encrypted)
        assert decrypted is None

    def test_v2_disabled_replay_protection(self):
        """v2 with max_age_ms=None disables replay protection."""
        import time
        import struct
        from shield.core import NONCE_SIZE, MAC_SIZE, _generate_keystream
        import hmac
        import hashlib

        s = Shield("password", "service", max_age_ms=None)

        # Create message with very old timestamp (should still decrypt)
        old_timestamp_ms = int(time.time() * 1000) - 100_000
        plaintext = b"old but valid"

        nonce = os.urandom(NONCE_SIZE)
        counter_bytes = struct.pack("<Q", 0)
        timestamp_bytes = struct.pack("<Q", old_timestamp_ms)
        pad_len = 32
        pad_len_byte = struct.pack("B", pad_len)
        padding = os.urandom(pad_len)

        data = counter_bytes + timestamp_bytes + pad_len_byte + padding + plaintext

        keystream = _generate_keystream(s.key, nonce, len(data))
        ciphertext = bytes(p ^ k for p, k in zip(data, keystream))
        mac = hmac.new(s.key, nonce + ciphertext, hashlib.sha256).digest()[:MAC_SIZE]
        encrypted = nonce + ciphertext + mac

        # Should decrypt successfully (no age check)
        decrypted = s.decrypt(encrypted)
        assert decrypted == plaintext


class TestQuickEncrypt:
    """Test quick_encrypt/quick_decrypt functions."""

    def test_basic(self):
        """Basic encrypt/decrypt cycle."""
        key = os.urandom(32)
        plaintext = b"Hello!"
        encrypted = quick_encrypt(key, plaintext)
        decrypted = quick_decrypt(key, encrypted)
        assert decrypted == plaintext

    def test_wrong_key_fails(self):
        """Wrong key returns None."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        encrypted = quick_encrypt(key1, b"secret")
        decrypted = quick_decrypt(key2, encrypted)
        assert decrypted is None

    def test_tampered_fails(self):
        """Tampered ciphertext returns None."""
        key = os.urandom(32)
        encrypted = quick_encrypt(key, b"secret")
        tampered = encrypted[:10] + bytes([encrypted[10] ^ 0xFF]) + encrypted[11:]
        decrypted = quick_decrypt(key, tampered)
        assert decrypted is None

    def test_empty_input(self):
        """Empty plaintext works."""
        key = os.urandom(32)
        encrypted = quick_encrypt(key, b"")
        decrypted = quick_decrypt(key, encrypted)
        assert decrypted == b""

    def test_short_ciphertext_fails(self):
        """Too-short ciphertext returns None."""
        key = os.urandom(32)
        decrypted = quick_decrypt(key, b"short")
        assert decrypted is None
