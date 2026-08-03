"""Tests for Shield ratchet (forward secrecy)."""

import os
import struct
import pytest
from shield.ratchet import RatchetSession, _hmac_sha256, _derive_msg_subkeys, _generate_keystream


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


class TestFamilyAVector:
    """
    Cross-language test vectors verifying Python produces byte-identical
    output to the Rust reference implementation (Family A).

    Vector source: cargo test test_ratchet_vector -- --nocapture
    Reference: tests/ratchet_vectors_family_a.json
    """

    ROOT_KEY = bytes([0x42] * 32)
    FIXED_NONCE = bytes(range(16))  # 0x00..0x0f
    PLAINTEXT = b"Hello, Shield!"

    # Expected intermediate values (from Rust)
    EXPECTED_SEND_CHAIN_AFTER_INIT = bytes.fromhex(
        "5f752670683f72648656859b419c2fe04fcb7aec7816e662cbabf95381e4ec8b"
    )
    EXPECTED_MSG_KEY = bytes.fromhex(
        "1648831a828afa9e4b05fe90dc2140d5047ee5c1d62d2d512305420b4a4ba454"
    )
    EXPECTED_NEW_SEND_CHAIN = bytes.fromhex(
        "e59765f901663d80148bd9e621405385b1b64860473d13a5bfb65bc99173611d"
    )
    EXPECTED_ENC_KEY = bytes.fromhex(
        "8a188f89639740e97eb858c764e440e302850a477bdfcee867ee538111fa3780"
    )
    EXPECTED_MAC_KEY = bytes.fromhex(
        "7d093d8c134df1cdc03e66e01742c7c7a2640024070cb9e7d4f4b04f38d77dbf"
    )
    # Full frame: nonce(16) || ciphertext || mac(16)
    EXPECTED_FRAME = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "0ef3fefe86d0a95843da2ae531ad4af1"
        "1ba8a474aa86c024fdb7113afa2cb0d0"
        "f3cb423bd6a7"
    )

    def test_chain_init_matches_rust(self):
        """HMAC-SHA256(root, 'send') must match Rust derive_chain_key."""
        send_chain = _hmac_sha256(self.ROOT_KEY, b"send")
        assert send_chain == self.EXPECTED_SEND_CHAIN_AFTER_INIT, (
            f"send_chain mismatch:\n  Python: {send_chain.hex()}\n"
            f"  Rust:   {self.EXPECTED_SEND_CHAIN_AFTER_INIT.hex()}"
        )

    def test_ratchet_chain_msg_key_matches_rust(self):
        """HMAC-SHA256(send_chain, 'message') must match Rust ratchet_chain msg_key."""
        send_chain = _hmac_sha256(self.ROOT_KEY, b"send")
        msg_key = _hmac_sha256(send_chain, b"message")
        assert msg_key == self.EXPECTED_MSG_KEY, (
            f"msg_key mismatch:\n  Python: {msg_key.hex()}\n"
            f"  Rust:   {self.EXPECTED_MSG_KEY.hex()}"
        )

    def test_ratchet_chain_new_chain_matches_rust(self):
        """HMAC-SHA256(send_chain, 'chain') must match Rust new_chain."""
        send_chain = _hmac_sha256(self.ROOT_KEY, b"send")
        new_chain = _hmac_sha256(send_chain, b"chain")
        assert new_chain == self.EXPECTED_NEW_SEND_CHAIN

    def test_subkeys_match_rust(self):
        """enc_key and mac_key must match Rust derive_msg_subkeys."""
        send_chain = _hmac_sha256(self.ROOT_KEY, b"send")
        msg_key = _hmac_sha256(send_chain, b"message")
        enc_key, mac_key = _derive_msg_subkeys(msg_key)
        assert enc_key == self.EXPECTED_ENC_KEY, (
            f"enc_key mismatch:\n  Python: {enc_key.hex()}\n"
            f"  Rust:   {self.EXPECTED_ENC_KEY.hex()}"
        )
        assert mac_key == self.EXPECTED_MAC_KEY

    def test_full_frame_matches_rust(self):
        """
        Full encrypt frame with fixed nonce must be byte-identical to Rust output.

        Verifies: nonce || HMAC_keystream_XOR(ctr_le64 || plaintext) || mac(16)
        """
        send_chain = _hmac_sha256(self.ROOT_KEY, b"send")
        msg_key = _hmac_sha256(send_chain, b"message")
        enc_key, mac_key = _derive_msg_subkeys(msg_key)

        counter = 0
        counter_bytes = struct.pack("<Q", counter)
        data = counter_bytes + self.PLAINTEXT

        keystream = _generate_keystream(enc_key, self.FIXED_NONCE, len(data))
        ciphertext = bytes(p ^ k for p, k in zip(data, keystream))
        mac = _hmac_sha256(mac_key, self.FIXED_NONCE + ciphertext)[:16]
        frame = self.FIXED_NONCE + ciphertext + mac

        assert frame == self.EXPECTED_FRAME, (
            f"Frame mismatch:\n  Python: {frame.hex()}\n"
            f"  Rust:   {self.EXPECTED_FRAME.hex()}"
        )

    def test_roundtrip_with_rust_vector(self):
        """
        Bob (non-initiator) must decrypt the Rust-produced frame byte-for-byte.

        This is the end-to-end cross-language compatibility test: a frame
        produced by Rust (with fixed nonce) must be decryptable by Python
        using the same root_key.
        """
        bob = RatchetSession(self.ROOT_KEY, is_initiator=False)
        # Bob's recv chain = HMAC(root, "send") (he receives what Alice/initiator sends)
        decrypted = bob.decrypt(self.EXPECTED_FRAME)
        assert decrypted == self.PLAINTEXT, (
            f"Cross-language decrypt failed:\n  got: {decrypted!r}\n"
            f"  expected: {self.PLAINTEXT!r}"
        )
