"""Tests for the v5 unified ratchet pilot (ratchet_v2.py)."""
import os
import pytest
from cryptography.exceptions import InvalidTag
from shield.ratchet_v2 import RatchetSessionV2


# ---------------------------------------------------------------------------
# Basic key derivation
# ---------------------------------------------------------------------------


def test_ratchet_produces_different_message_keys_each_step():
    """Each ratchet step should produce a different message key."""
    session = RatchetSessionV2(b"\x01" * 32)
    key1 = session.ratchet_step()

    session2 = RatchetSessionV2(b"\x01" * 32)
    session2.ratchet_step()  # advance one step
    key2 = session2.ratchet_step()  # second step

    assert key1 != key2


def test_synchronized_sessions_produce_same_message_keys():
    """Two sessions initialized from the same chain_key must produce identical keys."""
    initial_key = b"\xab" * 32
    sender = RatchetSessionV2(initial_key)
    receiver = RatchetSessionV2(initial_key)

    for _ in range(10):
        assert sender.ratchet_step() == receiver.ratchet_step()


def test_message_key_is_32_bytes():
    """ratchet_step must return exactly 32 bytes."""
    session = RatchetSessionV2(b"\xde" * 32)
    key = session.ratchet_step()
    assert len(key) == 32


def test_chain_key_advances_deterministically():
    """Step N of two identically seeded sessions produces the same key."""
    initial_key = b"\x11" * 32
    key_a = RatchetSessionV2(initial_key).ratchet_step()
    key_b = RatchetSessionV2(initial_key).ratchet_step()
    assert key_a == key_b


# ---------------------------------------------------------------------------
# from_root_key / derive_initial_chain_key
# ---------------------------------------------------------------------------


def test_from_root_key_returns_valid_session():
    """from_root_key should produce a usable session with a non-trivial key."""
    root_key = b"\xca" * 32
    dh_output = b"\xfe" * 32
    session = RatchetSessionV2.from_root_key(root_key, dh_output)
    key = session.ratchet_step()
    assert len(key) == 32
    assert key != root_key
    assert key != dh_output


def test_from_root_key_is_deterministic():
    """Same root_key + dh_output must produce the same initial chain key."""
    root_key = b"\xca" * 32
    dh_output = b"\xfe" * 32
    s1 = RatchetSessionV2.from_root_key(root_key, dh_output)
    s2 = RatchetSessionV2.from_root_key(root_key, dh_output)
    assert s1.ratchet_step() == s2.ratchet_step()


def test_different_root_keys_produce_different_chain_keys():
    """Different root keys must produce different initial chain keys."""
    dh_output = b"\xfe" * 32
    ck1 = RatchetSessionV2.derive_initial_chain_key(b"\x00" * 32, dh_output)
    ck2 = RatchetSessionV2.derive_initial_chain_key(b"\xff" * 32, dh_output)
    assert ck1 != ck2


# ---------------------------------------------------------------------------
# Encrypt / decrypt roundtrip
# ---------------------------------------------------------------------------


def test_encrypt_decrypt_roundtrip():
    """Sender and receiver synchronized on the same chain_key must interoperate."""
    initial_key = b"\x42" * 32
    sender = RatchetSessionV2(initial_key)
    receiver = RatchetSessionV2(initial_key)

    plaintext = b"Hello, Shield v5!"
    ciphertext = sender.encrypt(plaintext)
    recovered = receiver.decrypt(ciphertext)
    assert recovered == plaintext


def test_encrypt_decrypt_multiple_messages_in_order():
    """Multiple sequential messages must all decrypt correctly."""
    initial_key = b"\x7f" * 32
    sender = RatchetSessionV2(initial_key)
    receiver = RatchetSessionV2(initial_key)

    messages = [b"message one", b"message two", b"message three", b"", b"x" * 1000]
    for msg in messages:
        ct = sender.encrypt(msg)
        assert receiver.decrypt(ct) == msg


def test_encrypt_produces_different_ciphertext_for_same_plaintext():
    """Same plaintext encrypted twice must yield different ciphertext (random nonce)."""
    initial_key = b"\x99" * 32
    session = RatchetSessionV2(initial_key)
    ct1 = session.encrypt(b"same message")

    session2 = RatchetSessionV2(initial_key)
    session2.ratchet_step()  # advance to step 2
    ct2 = session2.encrypt(b"same message")

    assert ct1 != ct2


def test_ciphertext_includes_nonce():
    """Encrypted output must be longer than plaintext by at least nonce + GCM tag."""
    initial_key = b"\x55" * 32
    session = RatchetSessionV2(initial_key)
    plaintext = b"test"
    ct = session.encrypt(plaintext)
    # 12-byte nonce + 16-byte GCM tag + plaintext
    assert len(ct) == len(plaintext) + 12 + 16


# ---------------------------------------------------------------------------
# Authentication failure
# ---------------------------------------------------------------------------


def test_tampered_ciphertext_raises():
    """A tampered ciphertext must fail authentication (InvalidTag)."""
    initial_key = b"\xaa" * 32
    sender = RatchetSessionV2(initial_key)
    receiver = RatchetSessionV2(initial_key)

    ct = sender.encrypt(b"secret")
    # Flip a byte in the ciphertext body (after the 12-byte nonce)
    tampered = ct[:13] + bytes([ct[13] ^ 0xFF]) + ct[14:]

    with pytest.raises(InvalidTag):
        receiver.decrypt(tampered)


def test_wrong_key_raises():
    """A receiver with a different chain_key must fail authentication."""
    sender = RatchetSessionV2(b"\xaa" * 32)
    receiver = RatchetSessionV2(b"\xbb" * 32)

    ct = sender.encrypt(b"hello")
    with pytest.raises(InvalidTag):
        receiver.decrypt(ct)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_chain_key_wrong_length_raises():
    """Constructing a session with a key that is not 32 bytes must raise ValueError."""
    with pytest.raises(ValueError, match="32 bytes"):
        RatchetSessionV2(b"\x00" * 16)


def test_decrypt_too_short_raises():
    """Decrypting a ciphertext that is too short must raise ValueError."""
    session = RatchetSessionV2(b"\x00" * 32)
    with pytest.raises(ValueError, match="too short"):
        session.decrypt(b"\x00" * 5)
