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
