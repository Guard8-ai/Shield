"""Tests for Shield ratchet (forward secrecy)."""

import os
import pytest
from shield.ratchet import RatchetSession


class TestRatchetSession:
    """Test RatchetSession class."""

    def test_basic_communication(self):
        """Basic message exchange."""
        root_key = os.urandom(32)
        alice = RatchetSession(root_key, is_initiator=True)
        bob = RatchetSession(root_key, is_initiator=False)

        # Alice sends to Bob
        plaintext = b"Hello Bob!"
        encrypted = alice.encrypt(plaintext)
        decrypted = bob.decrypt(encrypted)
        assert decrypted == plaintext

    def test_bidirectional(self):
        """Messages in both directions."""
        root_key = os.urandom(32)
        alice = RatchetSession(root_key, is_initiator=True)
        bob = RatchetSession(root_key, is_initiator=False)

        # Alice -> Bob
        enc1 = alice.encrypt(b"Hi Bob!")
        dec1 = bob.decrypt(enc1)
        assert dec1 == b"Hi Bob!"

        # Bob -> Alice
        enc2 = bob.encrypt(b"Hi Alice!")
        dec2 = alice.decrypt(enc2)
        assert dec2 == b"Hi Alice!"

        # Alice -> Bob again
        enc3 = alice.encrypt(b"How are you?")
        dec3 = bob.decrypt(enc3)
        assert dec3 == b"How are you?"

    def test_forward_secrecy(self):
        """Each message uses unique key."""
        root_key = os.urandom(32)
        alice = RatchetSession(root_key, is_initiator=True)

        # Encrypt same message twice - should produce different ciphertext
        enc1 = alice.encrypt(b"same message")
        enc2 = alice.encrypt(b"same message")
        assert enc1 != enc2

    def test_replay_protection(self):
        """Replayed messages fail."""
        root_key = os.urandom(32)
        alice = RatchetSession(root_key, is_initiator=True)
        bob = RatchetSession(root_key, is_initiator=False)

        encrypted = alice.encrypt(b"original")
        decrypted = bob.decrypt(encrypted)
        assert decrypted == b"original"

        # Replay the same message - should fail
        replayed = bob.decrypt(encrypted)
        assert replayed is None

    def test_out_of_order_fails(self):
        """Out-of-order messages fail."""
        root_key = os.urandom(32)
        alice = RatchetSession(root_key, is_initiator=True)
        bob = RatchetSession(root_key, is_initiator=False)

        # Alice sends two messages
        enc1 = alice.encrypt(b"message 1")
        enc2 = alice.encrypt(b"message 2")

        # Bob tries to decrypt out of order
        dec2 = bob.decrypt(enc2)  # Should fail - expecting message 1
        assert dec2 is None

    def test_wrong_root_key_fails(self):
        """Different root keys fail."""
        alice = RatchetSession(os.urandom(32), is_initiator=True)
        bob = RatchetSession(os.urandom(32), is_initiator=False)

        encrypted = alice.encrypt(b"secret")
        decrypted = bob.decrypt(encrypted)
        assert decrypted is None

    def test_counters(self):
        """Counters increment correctly."""
        root_key = os.urandom(32)
        alice = RatchetSession(root_key, is_initiator=True)
        bob = RatchetSession(root_key, is_initiator=False)

        assert alice.send_counter == 0
        assert bob.recv_counter == 0

        enc1 = alice.encrypt(b"msg1")
        assert alice.send_counter == 1

        bob.decrypt(enc1)
        assert bob.recv_counter == 1

        enc2 = alice.encrypt(b"msg2")
        assert alice.send_counter == 2

    def test_many_messages(self):
        """Many messages work correctly."""
        root_key = os.urandom(32)
        alice = RatchetSession(root_key, is_initiator=True)
        bob = RatchetSession(root_key, is_initiator=False)

        for i in range(100):
            msg = f"Message {i}".encode()
            encrypted = alice.encrypt(msg)
            decrypted = bob.decrypt(encrypted)
            assert decrypted == msg

    def test_large_message(self):
        """Large messages work."""
        root_key = os.urandom(32)
        alice = RatchetSession(root_key, is_initiator=True)
        bob = RatchetSession(root_key, is_initiator=False)

        plaintext = os.urandom(100 * 1024)  # 100KB
        encrypted = alice.encrypt(plaintext)
        decrypted = bob.decrypt(encrypted)
        assert decrypted == plaintext

    def test_tampered_message_fails(self):
        """Tampered messages fail."""
        root_key = os.urandom(32)
        alice = RatchetSession(root_key, is_initiator=True)
        bob = RatchetSession(root_key, is_initiator=False)

        encrypted = alice.encrypt(b"secret")
        tampered = encrypted[:20] + bytes([encrypted[20] ^ 0xFF]) + encrypted[21:]
        decrypted = bob.decrypt(tampered)
        assert decrypted is None
