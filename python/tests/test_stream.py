"""Tests for Shield streaming encryption."""

import os
import tempfile
import pytest
from shield.stream import StreamCipher


class TestStreamCipher:
    """Test StreamCipher class."""

    def test_encrypt_decrypt_memory(self):
        """Basic in-memory encrypt/decrypt."""
        key = os.urandom(32)
        cipher = StreamCipher(key)
        plaintext = b"Hello, streaming world!"
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == plaintext

    def test_from_password(self):
        """Create cipher from password."""
        salt = os.urandom(16)
        cipher = StreamCipher.from_password("password", salt)
        plaintext = b"secret data"
        encrypted = cipher.encrypt(plaintext)

        # Same password + salt should decrypt
        cipher2 = StreamCipher.from_password("password", salt)
        decrypted = cipher2.decrypt(encrypted)
        assert decrypted == plaintext

    def test_wrong_password_fails(self):
        """Wrong password raises ValueError."""
        salt = os.urandom(16)
        cipher1 = StreamCipher.from_password("correct", salt)
        cipher2 = StreamCipher.from_password("wrong", salt)
        encrypted = cipher1.encrypt(b"secret")

        with pytest.raises(ValueError):
            cipher2.decrypt(encrypted)

    def test_large_data(self):
        """Large data with multiple chunks."""
        key = os.urandom(32)
        cipher = StreamCipher(key, chunk_size=1024)  # Small chunks
        plaintext = os.urandom(10 * 1024)  # 10KB
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_file(self):
        """File encryption/decryption."""
        key = os.urandom(32)
        cipher = StreamCipher(key)

        with tempfile.TemporaryDirectory() as tmpdir:
            in_path = os.path.join(tmpdir, "input.bin")
            enc_path = os.path.join(tmpdir, "encrypted.bin")
            out_path = os.path.join(tmpdir, "output.bin")

            # Create input file
            plaintext = os.urandom(100 * 1024)  # 100KB
            with open(in_path, "wb") as f:
                f.write(plaintext)

            # Encrypt
            cipher.encrypt_file(in_path, enc_path)

            # Verify encrypted file is different
            with open(enc_path, "rb") as f:
                encrypted = f.read()
            assert encrypted != plaintext

            # Decrypt
            cipher.decrypt_file(enc_path, out_path)

            # Verify output matches input
            with open(out_path, "rb") as f:
                decrypted = f.read()
            assert decrypted == plaintext

    def test_streaming_iterator(self):
        """Test streaming iterator interface."""
        key = os.urandom(32)
        cipher = StreamCipher(key, chunk_size=100)

        # Create chunks
        chunks = [os.urandom(100) for _ in range(10)]
        plaintext = b"".join(chunks)

        # Encrypt streaming
        encrypted_chunks = list(cipher.encrypt_stream(iter(chunks)))
        encrypted = b"".join(encrypted_chunks)

        # Decrypt
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == plaintext

    def test_empty_data(self):
        """Empty data works."""
        key = os.urandom(32)
        cipher = StreamCipher(key)
        encrypted = cipher.encrypt(b"")
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == b""

    def test_tampered_chunk_fails(self):
        """Tampered chunk raises ValueError."""
        key = os.urandom(32)
        cipher = StreamCipher(key)
        encrypted = cipher.encrypt(b"secret data here")

        # Tamper in the middle
        tampered = encrypted[:30] + bytes([encrypted[30] ^ 0xFF]) + encrypted[31:]

        with pytest.raises(ValueError):
            cipher.decrypt(tampered)
