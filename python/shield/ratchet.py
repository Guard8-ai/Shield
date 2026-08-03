"""
Shield Ratchet - Forward secrecy through key ratcheting.

Each message uses a new key derived from previous.
Compromise of current key doesn't reveal past messages.

Based on Signal's Double Ratchet (simplified symmetric version).

WIRE FORMAT VERSION: Family A (aligned to Rust HMAC reference as of 2026-08-03)

This module was previously Family B (SHA256 concatenation chain). It has been
realigned to Family A so that Python and Rust produce byte-identical ciphertext
given the same root key, nonce, and counter. The three changes made:

  1. Chain KDF: SHA256(root || label) -> HMAC-SHA256(root, label)
     _derive_chain_key and _ratchet_chain now use HMAC, matching ratchet.rs
     derive_chain_key() and ratchet_chain().

  2. Subkey expansion: single msg_key -> enc_key + mac_key
     _derive_msg_subkeys splits the message key into a separate encryption
     subkey and authentication subkey, matching ratchet.rs derive_msg_subkeys().

  3. Keystream: SHA256(key || nonce || ctr) -> HMAC-SHA256(enc_key, nonce || ctr)
     _generate_keystream now uses HMAC with enc_key, matching ratchet.rs
     encrypt_with_key(). The MAC also uses mac_key instead of msg_key.

Wire format (unchanged from Family B): nonce(16) || ciphertext || mac_truncated(16)
Counter is encrypted inside ciphertext (first 8 bytes of XOR plaintext, LE uint64).

INCOMPATIBLE with old Family B ciphertext. Existing Family B sessions must be
reset. See docs/ratchet-realignment-spec.md for migration guidance.

Cross-language vector (from Rust, root_key=0x42*32, nonce=0x000102...0f):
  intermediate.send_chain_after_init:
    5f752670683f72648656859b419c2fe04fcb7aec7816e662cbabf95381e4ec8b
  ciphertext_hex for "Hello, Shield!" at counter=0:
    000102030405060708090a0b0c0d0e0f
    0ef3fefe86d0a95843da2ae531ad4af1
    1ba8a474aa86c024fdb7113afa2cb0d0
    f3cb423bd6a7

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


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256(key, data) -> 32 bytes."""
    return hmac.new(key, data, hashlib.sha256).digest()


def _derive_msg_subkeys(msg_key: bytes) -> Tuple[bytes, bytes]:
    """
    Derive enc_key and mac_key from a message key.

    Matches Rust: derive_msg_subkeys()
      enc_key = HMAC-SHA256(msg_key, "shield-ratchet-encrypt")
      mac_key = HMAC-SHA256(msg_key, "shield-ratchet-authenticate")
    """
    enc_key = _hmac_sha256(msg_key, b"shield-ratchet-encrypt")
    mac_key = _hmac_sha256(msg_key, b"shield-ratchet-authenticate")
    return enc_key, mac_key


def _generate_keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """
    Generate keystream using HMAC-SHA256 (Family A / Rust reference).

    Each 32-byte block = HMAC-SHA256(enc_key, nonce || block_counter_le32).
    Matches Rust: encrypt_with_key() keystream loop with enc_key.

    Previously (Family B): SHA256(key || nonce || block_counter_le32) with msg_key.
    """
    keystream = b""
    for i in range((length + 31) // 32):
        block_data = nonce + struct.pack("<I", i)
        keystream += _hmac_sha256(enc_key, block_data)
    return keystream[:length]


class RatchetSession:
    """
    Ratcheting session for forward secrecy.

    Each encrypt/decrypt advances the key chain,
    destroying previous keys automatically.

    Wire format: Family A (Rust HMAC reference). Compatible with Rust and WASM.
    NOT compatible with old Family B (Python pre-2026-08-03) or Family C.

    Security:
        - Compromise of current key doesn't reveal past messages
        - Each message encrypted with unique key
        - Replay protection via counters
        - Separate enc_key/mac_key subkeys prevent related-key attacks
    """

    def __init__(self, root_key: bytes, is_initiator: bool):
        """
        Create a new ratchet session from shared root key.

        Args:
            root_key: 32-byte shared secret from key exchange
            is_initiator: True if this party initiated the session
        """
        # Derive separate send/receive chains using HMAC (Family A)
        if is_initiator:
            send_label, recv_label = b"send", b"recv"
        else:
            send_label, recv_label = b"recv", b"send"

        self._send_chain = self._derive_chain_key(root_key, send_label)
        self._recv_chain = self._derive_chain_key(root_key, recv_label)
        self._send_counter = 0
        self._recv_counter = 0

    def _derive_chain_key(self, root: bytes, label: bytes) -> bytes:
        """
        Derive chain key from root and label using HMAC-SHA256.

        Family A (Rust): HMAC-SHA256(root, label)
        Previously Family B: SHA256(root || label)

        Matches Rust: derive_chain_key()
        """
        return _hmac_sha256(root, label)

    def _ratchet_chain(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        Advance chain forward, returning (new_chain_key, message_key).

        Family A (Rust):
          new_chain = HMAC-SHA256(chain_key, "chain")
          msg_key   = HMAC-SHA256(chain_key, "message")

        Previously Family B: SHA256(chain_key || "chain/message")

        Matches Rust: ratchet_chain()
        """
        new_chain = _hmac_sha256(chain_key, b"chain")
        msg_key = _hmac_sha256(chain_key, b"message")
        return new_chain, msg_key

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt a message with forward secrecy.

        Advances the send chain - previous keys are destroyed.

        Args:
            plaintext: Message to encrypt

        Returns:
            Encrypted message (Family A wire format)

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
            messages will fail authentication. A failed message does
            NOT advance the receive chain, so the session stays in
            sync and the next genuine in-order message still decrypts.
        """
        # Derive the next chain key and message key WITHOUT committing them:
        # if the chain advanced before authentication, a single forged or
        # corrupted frame would permanently desynchronize the session (every
        # later genuine message would use the wrong key). State is committed
        # only after both the MAC and the counter verify.
        next_chain, msg_key = self._ratchet_chain(self._recv_chain)

        # Decrypt with message key
        result = self._decrypt_with_key(msg_key, ciphertext)
        if result is None:
            return None

        plaintext, counter = result

        # Verify counter (replay protection)
        if counter != self._recv_counter:
            return None

        # Commit: advance the receive chain only after successful
        # authentication and counter verification.
        self._recv_chain = next_chain
        self._recv_counter += 1
        return plaintext

    def _encrypt_with_key(
        self, msg_key: bytes, plaintext: bytes, counter: int
    ) -> bytes:
        """
        Encrypt with specific message key (Family A / Rust reference).

        Derives enc_key and mac_key from msg_key, uses HMAC keystream.
        Matches Rust: encrypt_with_key()
        """
        enc_key, mac_key = _derive_msg_subkeys(msg_key)

        nonce = os.urandom(16)
        counter_bytes = struct.pack("<Q", counter)

        # Data: counter || plaintext (counter encrypted inside ciphertext)
        data = counter_bytes + plaintext

        # Generate keystream with enc_key via HMAC
        keystream = _generate_keystream(enc_key, nonce, len(data))

        # XOR encrypt
        ciphertext = bytes(p ^ k for p, k in zip(data, keystream))

        # MAC with mac_key over nonce || ciphertext
        mac = _hmac_sha256(mac_key, nonce + ciphertext)[:16]

        return nonce + ciphertext + mac

    def _decrypt_with_key(
        self, msg_key: bytes, encrypted: bytes
    ) -> Optional[Tuple[bytes, int]]:
        """
        Decrypt with specific message key (Family A / Rust reference).

        Returns (plaintext, counter) or None on auth failure.
        Matches Rust: decrypt_with_key()
        """
        if len(encrypted) < 40:  # 16 nonce + 8 counter + 16 mac (minimum)
            return None

        enc_key, mac_key = _derive_msg_subkeys(msg_key)

        nonce = encrypted[:16]
        ciphertext = encrypted[16:-16]
        mac = encrypted[-16:]

        # Verify MAC with mac_key
        expected_mac = _hmac_sha256(mac_key, nonce + ciphertext)[:16]
        if not hmac.compare_digest(mac, expected_mac):
            return None

        # Decrypt with enc_key keystream
        keystream = _generate_keystream(enc_key, nonce, len(ciphertext))
        decrypted = bytes(c ^ k for c, k in zip(ciphertext, keystream))

        # Parse counter (first 8 bytes, little-endian uint64)
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
