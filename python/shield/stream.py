"""
Shield Stream - Streaming encryption for large files.

Processes data in chunks with constant memory usage.
Each chunk is independently authenticated.

Example:
    >>> from shield.stream import StreamCipher
    >>> cipher = StreamCipher.from_password("password", b"salt")
    >>> cipher.encrypt_file("large.bin", "large.bin.enc")
    >>> cipher.decrypt_file("large.bin.enc", "large.bin.dec")
"""

import os
import hmac
import hashlib
import struct
from typing import Iterator, Optional

# Default chunk size: 64KB
DEFAULT_CHUNK_SIZE = 64 * 1024


def _derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """Derive key from password using PBKDF2."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)


def _generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate keystream using SHA256."""
    keystream = b""
    for i in range((length + 31) // 32):
        keystream += hashlib.sha256(key + nonce + struct.pack("<I", i)).digest()
    return keystream[:length]


def _encrypt_block(key: bytes, data: bytes) -> bytes:
    """Encrypt a single block with authentication."""
    nonce = os.urandom(16)
    keystream = _generate_keystream(key, nonce, len(data))
    ciphertext = bytes(a ^ b for a, b in zip(data, keystream))
    mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:16]
    return nonce + ciphertext + mac


def _decrypt_block(key: bytes, encrypted: bytes) -> Optional[bytes]:
    """Decrypt a single block with verification."""
    if len(encrypted) < 32:
        return None
    nonce = encrypted[:16]
    ciphertext = encrypted[16:-16]
    mac = encrypted[-16:]

    expected_mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(mac, expected_mac):
        return None

    keystream = _generate_keystream(key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, keystream))


class StreamCipher:
    """
    Streaming encryption for large files.

    Processes data in chunks with constant memory usage.
    Each chunk is independently authenticated, allowing:
    - Early detection of tampering
    - Constant memory regardless of file size
    - Potential for parallel processing
    """

    def __init__(self, key: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE):
        """
        Initialize with encryption key.

        Args:
            key: 32-byte symmetric key
            chunk_size: Size of each chunk (default: 64KB)
        """
        self.key = key
        self.chunk_size = chunk_size

    @classmethod
    def from_password(
        cls,
        password: str,
        salt: bytes,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> "StreamCipher":
        """
        Create StreamCipher from password.

        Args:
            password: User's password
            salt: Salt for key derivation
            chunk_size: Size of each chunk (default: 64KB)

        Returns:
            StreamCipher instance
        """
        key = _derive_key(password, salt)
        return cls(key, chunk_size)

    def encrypt_stream(self, data_iter: Iterator[bytes]) -> Iterator[bytes]:
        """
        Encrypt streaming data.

        Args:
            data_iter: Iterator yielding data chunks

        Yields:
            Encrypted chunks

        Example:
            >>> cipher = StreamCipher(key)
            >>> with open('in.bin', 'rb') as f:
            ...     chunks = iter(lambda: f.read(64*1024), b'')
            ...     for enc in cipher.encrypt_stream(chunks):
            ...         out.write(enc)
        """
        # Header: chunk_size(4) || stream_salt(16)
        stream_salt = os.urandom(16)
        yield struct.pack("<I", self.chunk_size) + stream_salt

        chunk_num = 0
        for data in data_iter:
            if not data:
                break

            # Derive per-chunk key
            chunk_key = hashlib.sha256(
                self.key + stream_salt + struct.pack("<Q", chunk_num)
            ).digest()

            # Encrypt chunk
            encrypted = _encrypt_block(chunk_key, data)

            # Prepend length
            yield struct.pack("<I", len(encrypted)) + encrypted
            chunk_num += 1

        # End marker
        yield struct.pack("<I", 0)

    def decrypt_stream(self, enc_iter: Iterator[bytes]) -> Iterator[bytes]:
        """
        Decrypt streaming data.

        Args:
            enc_iter: Iterator yielding encrypted chunks

        Yields:
            Decrypted chunks

        Raises:
            ValueError: If authentication fails
        """
        # Read header
        header = next(enc_iter)
        _chunk_size = struct.unpack("<I", header[:4])[0]
        stream_salt = header[4:20]

        chunk_num = 0
        buffer = b""

        for data in enc_iter:
            buffer += data

            while len(buffer) >= 4:
                enc_len = struct.unpack("<I", buffer[:4])[0]
                if enc_len == 0:  # End marker
                    return

                if len(buffer) < 4 + enc_len:
                    break

                encrypted = buffer[4 : 4 + enc_len]
                buffer = buffer[4 + enc_len :]

                # Derive per-chunk key
                chunk_key = hashlib.sha256(
                    self.key + stream_salt + struct.pack("<Q", chunk_num)
                ).digest()

                # Decrypt
                decrypted = _decrypt_block(chunk_key, encrypted)
                if decrypted is None:
                    raise ValueError(f"Chunk {chunk_num} authentication failed")

                yield decrypted
                chunk_num += 1

    def encrypt_file(self, in_path: str, out_path: str) -> None:
        """
        Encrypt a file.

        Args:
            in_path: Path to input file
            out_path: Path to output file
        """
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            chunks = iter(lambda: fin.read(self.chunk_size), b"")
            for encrypted in self.encrypt_stream(chunks):
                fout.write(encrypted)

    def decrypt_file(self, in_path: str, out_path: str) -> None:
        """
        Decrypt a file.

        Args:
            in_path: Path to encrypted file
            out_path: Path to output file

        Raises:
            ValueError: If authentication fails
        """

        def reader():
            with open(in_path, "rb") as f:
                # First yield the header (20 bytes: 4 chunk_size + 16 salt)
                header = f.read(20)
                if header:
                    yield header
                # Then yield rest of file in chunks
                while True:
                    data = f.read(self.chunk_size + 48)  # chunk + overhead
                    if not data:
                        break
                    yield data

        with open(out_path, "wb") as fout:
            for decrypted in self.decrypt_stream(reader()):
                fout.write(decrypted)

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data in memory (convenience method).

        Args:
            data: Data to encrypt

        Returns:
            Encrypted data
        """
        result = b""
        for chunk in self.encrypt_stream(iter([data])):
            result += chunk
        return result

    def decrypt(self, encrypted: bytes) -> bytes:
        """
        Decrypt data in memory (convenience method).

        Args:
            encrypted: Encrypted data

        Returns:
            Decrypted data
        """
        # Split header from rest for decrypt_stream which expects header first
        header = encrypted[:20]  # 4 bytes chunk_size + 16 bytes salt
        rest = encrypted[20:]

        result = b""
        for chunk in self.decrypt_stream(iter([header, rest])):
            result += chunk
        return result
