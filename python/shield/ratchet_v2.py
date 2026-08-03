"""
Shield v5 unified ratchet — reference implementation.

Uses HKDF-SHA256 for chain and message key derivation, based on the
Signal Double Ratchet paper. This is the proposed standard for all
language bindings in v5.

NOT compatible with v4 ratchet families (A/B/C) — see
docs/design/ratchet-realignment.md for the full analysis.

Design:
    chain_key_next = HKDFExpand(prk=chain_key, info="shield-ratchet-chain", len=32)
    message_key    = HKDFExpand(prk=chain_key, info="shield-ratchet-msg",   len=32)

Root ratchet (session setup from DH output):
    chain_key = HKDF(salt=root_key, ikm=dh_output, info="shield-ratchet-root", len=32)

This module is intentionally standalone — it does not import shield.core so
it can be ported to other languages without understanding the full codebase.
Encryption uses AES-256-GCM from the `cryptography` library (already a Shield
dependency).
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

RATCHET_CHAIN_INFO = b"shield-ratchet-chain"
RATCHET_MSG_INFO = b"shield-ratchet-msg"
RATCHET_ROOT_INFO = b"shield-ratchet-root"

# AES-256-GCM nonce size
_GCM_NONCE_SIZE = 12


class RatchetSessionV2:
    """
    Shield v5 unified ratchet session.

    Each send/receive advances the symmetric ratchet, deriving fresh
    chain and message keys using HKDF-SHA256.

    Usage::

        # Session setup: both parties derive the same initial chain_key
        # from their DH-negotiated root_key and any agreed dh_output.
        chain_key = RatchetSessionV2.derive_initial_chain_key(root_key, dh_output)

        sender   = RatchetSessionV2(chain_key)
        receiver = RatchetSessionV2(chain_key)

        ciphertext = sender.encrypt(b"hello")
        plaintext  = receiver.decrypt(ciphertext)
    """

    def __init__(self, chain_key: bytes) -> None:
        """
        Initialize from a 32-byte chain key.

        Args:
            chain_key: 32-byte symmetric chain key.  Both sender and receiver
                must be initialized with the same value for the session to stay
                in sync.

        Raises:
            ValueError: if chain_key is not exactly 32 bytes.
        """
        if len(chain_key) != 32:
            raise ValueError(f"chain_key must be 32 bytes, got {len(chain_key)}")
        self._chain_key: bytes = chain_key

    # ------------------------------------------------------------------
    # Class-level helpers
    # ------------------------------------------------------------------

    @classmethod
    def derive_initial_chain_key(cls, root_key: bytes, dh_output: bytes) -> bytes:
        """
        Derive an initial chain key from a root key and DH output.

        This is used during session setup (key exchange).  Both parties
        compute the same value from the shared secret.

        Args:
            root_key:  32-byte root / session key.
            dh_output: DH shared output (any length ≥ 1 byte; typically 32).

        Returns:
            32-byte initial chain key.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=root_key,
            info=RATCHET_ROOT_INFO,
            backend=default_backend(),
        )
        return hkdf.derive(dh_output)

    @classmethod
    def from_root_key(cls, root_key: bytes, dh_output: bytes) -> "RatchetSessionV2":
        """
        Create a session directly from a root key and DH output.

        Convenience wrapper around ``derive_initial_chain_key``.

        Args:
            root_key:  32-byte root key (e.g. from Shield key exchange).
            dh_output: DH shared output (any length ≥ 1 byte).

        Returns:
            A new RatchetSessionV2 ready for use.
        """
        chain_key = cls.derive_initial_chain_key(root_key, dh_output)
        return cls(chain_key)

    # ------------------------------------------------------------------
    # Core ratchet step
    # ------------------------------------------------------------------

    def ratchet_step(self) -> bytes:
        """
        Advance the ratchet by one step and return the message key.

        Derives a fresh ``chain_key_next`` and ``message_key`` from the
        current chain key, then replaces the internal chain key with
        ``chain_key_next``.  The old chain key is overwritten with zeros
        (best-effort — Python's garbage collector may retain copies).

        Returns:
            32-byte message key for encrypting/decrypting exactly one message.
        """
        expand = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=32,
            info=RATCHET_CHAIN_INFO,
            backend=default_backend(),
        )
        chain_key_next = expand.derive(self._chain_key)

        expand_msg = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=32,
            info=RATCHET_MSG_INFO,
            backend=default_backend(),
        )
        message_key = expand_msg.derive(self._chain_key)

        # Best-effort zeroize the old chain key before replacing it.
        old = bytearray(self._chain_key)
        for i in range(len(old)):
            old[i] = 0

        self._chain_key = chain_key_next
        return message_key

    # ------------------------------------------------------------------
    # Encrypt / decrypt
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext using the next ratchet step's message key.

        Uses AES-256-GCM.  Each call advances the ratchet, so the same
        plaintext produces different ciphertext on each call.

        Args:
            plaintext: Message to encrypt (any length, including empty).

        Returns:
            ``nonce(12) || gcm_ciphertext_with_tag`` as bytes.
        """
        message_key = self.ratchet_step()
        nonce = os.urandom(_GCM_NONCE_SIZE)
        aesgcm = AESGCM(message_key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ct

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext using the next ratchet step's message key.

        The ratchet advances only when decryption succeeds.

        Args:
            ciphertext: Output of a previous ``encrypt`` call.

        Returns:
            Decrypted plaintext.

        Raises:
            ValueError: if ciphertext is too short.
            cryptography.exceptions.InvalidTag: if authentication fails.
        """
        if len(ciphertext) < _GCM_NONCE_SIZE + 16:
            raise ValueError(
                f"ciphertext too short: expected ≥ {_GCM_NONCE_SIZE + 16} bytes, "
                f"got {len(ciphertext)}"
            )
        message_key = self.ratchet_step()
        nonce = ciphertext[:_GCM_NONCE_SIZE]
        ct = ciphertext[_GCM_NONCE_SIZE:]
        aesgcm = AESGCM(message_key)
        return aesgcm.decrypt(nonce, ct, None)
