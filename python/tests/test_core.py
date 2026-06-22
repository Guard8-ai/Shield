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

    def test_key_derivation_deterministic_with_explicit_salt(self):
        """Same password/service AND same explicit salt produces same key.

        NOTE: updated for CR-1. Previously this asserted that
        Shield(password, service) alone is deterministic -- that WAS the
        high-severity bug (every user of a service shared one key). Keys are
        now per-instance random by default; determinism only holds when the
        caller pins the salt explicitly (e.g. the recipient re-deriving from a
        header salt).
        """
        salt = os.urandom(16)
        s1 = Shield("password", "service", salt=salt)
        s2 = Shield("password", "service", salt=salt)
        assert s1.key == s2.key

    def test_different_services_different_keys(self):
        """Different services produce different keys (same fixed salt)."""
        salt = os.urandom(16)
        s1 = Shield("password", "service1", salt=salt)
        s2 = Shield("password", "service2", salt=salt)
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

    def _seal_with_timestamp(self, s, plaintext, timestamp_ms, pad_len=32):
        """Build a v4 password-mode ciphertext with an explicit timestamp.

        Uses the deterministic AEAD seal so a chosen (old) timestamp can be
        embedded to exercise the freshness window.
        """
        from shield.core import _seal_deterministic, NONCE_SIZE
        nonce = os.urandom(NONCE_SIZE)
        padding = os.urandom(pad_len)
        return _seal_deterministic(
            s._aead_key, s._suite, s._salt, nonce, timestamp_ms, pad_len, padding, plaintext
        )

    def test_v4_replay_protection_expired(self):
        """Freshness window: an expired message is rejected (v4 AEAD)."""
        import time
        s = Shield("password", "service", max_age_ms=1000)  # 1 second max age
        old_timestamp_ms = int(time.time() * 1000) - 2000
        encrypted = self._seal_with_timestamp(s, b"Old message", old_timestamp_ms)
        assert s.decrypt(encrypted) is None

    def test_v2_length_variation(self):
        """Multiple encryptions have different lengths (random padding)."""
        s = Shield("password", "service")
        plaintext = b"Same message"

        lengths = set()
        for _ in range(10):
            encrypted = s.encrypt(plaintext)
            lengths.add(len(encrypted))

        # Should have multiple different lengths due to random padding (32-128)
        assert len(lengths) > 1

    def test_old_format_rejected(self):
        """Legacy v3 (0x02 / 0x12) and unversioned blobs are rejected by v4.

        v4 uses version bytes 0x03 (password) / 0x13 (key); a leading byte from
        an older format does not dispatch, so decrypt() refuses it.
        """
        s = Shield("password", "service")
        # A well-formed-looking v3 password blob begins with 0x02.
        legacy_v3 = bytes([0x02]) + os.urandom(16 + 16 + 40 + 16)
        assert s.decrypt(legacy_v3) is None
        # An unversioned blob (random leading byte) is also rejected.
        assert s.decrypt(os.urandom(80)) is None

    def test_no_replay_on_expired_message(self):
        """Expired message is rejected by the freshness window (v4 AEAD)."""
        import time
        s = Shield("password", "service", max_age_ms=500)
        old_timestamp_ms = int(time.time() * 1000) - 2000
        encrypted = self._seal_with_timestamp(s, b"expired", old_timestamp_ms)
        assert s.decrypt(encrypted) is None

    def test_disabled_replay_protection(self):
        """max_age_ms=None disables the freshness window (v4 AEAD)."""
        import time
        s = Shield("password", "service", max_age_ms=None)
        old_timestamp_ms = int(time.time() * 1000) - 100_000
        encrypted = self._seal_with_timestamp(s, b"old but valid", old_timestamp_ms)
        assert s.decrypt(encrypted) == b"old but valid"


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
