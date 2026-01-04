"""
Shield Ratchet - Forward secrecy through key ratcheting.

Each message uses a new key derived from previous.
Compromise of current key doesn't reveal past messages.

Based on Signal's Double Ratchet (simplified symmetric version).

Example:
    >>> from shield.ratchet import RatchetSession
    >>> root_key = os.urandom(32)
    >>> alice = RatchetSession(root_key, is_initiator=True)
    >>> bob = RatchetSession(root_key, is_initiator=False)
    >>>
    >>> encrypted = alice.encrypt(b"Hello Bob!")
    >>> decrypted = bob.decrypt(encrypted)
"""

import os
import hmac
import hashlib
import struct
from typing import Optional, Tuple


def _generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate keystream using SHA256."""
    keystream = b""
    for i in range((length + 31) // 32):
        keystream += hashlib.sha256(key + nonce + struct.pack("<I", i)).digest()
    return keystream[:length]


class RatchetSession:
    """
    Ratcheting session for forward secrecy.

    Each encrypt/decrypt advances the key chain,
    destroying previous keys automatically.

    Security:
        - Compromise of current key doesn't reveal past messages
        - Each message encrypted with unique key
        - Replay protection via counters
    """

    def __init__(self, root_key: bytes, is_initiator: bool):
        """
        Create a new ratchet session from shared root key.

        Args:
            root_key: 32-byte shared secret from key exchange
            is_initiator: True if this party initiated the session
        """
        # Derive separate send/receive chains
        if is_initiator:
            send_label, recv_label = b"send", b"recv"
        else:
            send_label, recv_label = b"recv", b"send"

        self._send_chain = self._derive_chain_key(root_key, send_label)
        self._recv_chain = self._derive_chain_key(root_key, recv_label)
        self._send_counter = 0
        self._recv_counter = 0

    def _derive_chain_key(self, root: bytes, label: bytes) -> bytes:
        """Derive chain key from root and label."""
        return hashlib.sha256(root + label).digest()

    def _ratchet_chain(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        Advance chain forward, returning (new_chain_key, message_key).

        The old chain key is destroyed after this operation.
        """
        new_chain = hashlib.sha256(chain_key + b"chain").digest()
        msg_key = hashlib.sha256(chain_key + b"message").digest()
        return new_chain, msg_key

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt a message with forward secrecy.

        Advances the send chain - previous keys are destroyed.

        Args:
            plaintext: Message to encrypt

        Returns:
            Encrypted message

        Note:
            Each call advances the ratchet. The same plaintext
            will produce different ciphertext each time.
        """
        # Ratchet send chain
        self._send_chain, msg_key = self._ratchet_chain(self._send_chain)

        # Counter for ordering
        counter = self._send_counter
        self._send_counter += 1

        # Encrypt with message key
        return self._encrypt_with_key(msg_key, plaintext, counter)

    def decrypt(self, ciphertext: bytes) -> Optional[bytes]:
        """
        Decrypt a message with forward secrecy.

        Advances the receive chain - previous keys are destroyed.

        Args:
            ciphertext: Encrypted message from encrypt()

        Returns:
            Decrypted message, or None if authentication fails
            or message is out of order

        Note:
            Messages must be decrypted in order. Out-of-order
            messages will fail authentication.
        """
        # Ratchet receive chain
        self._recv_chain, msg_key = self._ratchet_chain(self._recv_chain)

        # Decrypt with message key
        result = self._decrypt_with_key(msg_key, ciphertext)
        if result is None:
            return None

        plaintext, counter = result

        # Verify counter (replay protection)
        if counter != self._recv_counter:
            return None

        self._recv_counter += 1
        return plaintext

    def _encrypt_with_key(
        self, key: bytes, plaintext: bytes, counter: int
    ) -> bytes:
        """Encrypt with specific message key."""
        nonce = os.urandom(16)
        counter_bytes = struct.pack("<Q", counter)

        # Data: counter || plaintext
        data = counter_bytes + plaintext

        # Generate keystream
        keystream = _generate_keystream(key, nonce, len(data))

        # XOR encrypt
        ciphertext = bytes(p ^ k for p, k in zip(data, keystream))

        # HMAC authenticate
        mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:16]

        return nonce + ciphertext + mac

    def _decrypt_with_key(
        self, key: bytes, encrypted: bytes
    ) -> Optional[Tuple[bytes, int]]:
        """Decrypt with specific message key, returns (plaintext, counter)."""
        if len(encrypted) < 40:  # 16 nonce + 8 counter + 16 mac
            return None

        nonce = encrypted[:16]
        ciphertext = encrypted[16:-16]
        mac = encrypted[-16:]

        # Verify MAC
        expected_mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[
            :16
        ]
        if not hmac.compare_digest(mac, expected_mac):
            return None

        # Decrypt
        keystream = _generate_keystream(key, nonce, len(ciphertext))
        decrypted = bytes(c ^ k for c, k in zip(ciphertext, keystream))

        # Parse counter
        counter = struct.unpack("<Q", decrypted[:8])[0]

        return decrypted[8:], counter

    @property
    def send_counter(self) -> int:
        """Get current send counter (for diagnostics)."""
        return self._send_counter

    @property
    def recv_counter(self) -> int:
        """Get current receive counter (for diagnostics)."""
        return self._recv_counter
