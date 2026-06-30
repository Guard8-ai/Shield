"""Security-fix tests for Shield core (CR-1 / CR-2 / CR-3).

These prove the deterministic-key bug is fixed (per-instance random salt),
the version byte / new wire format work, the iteration count was raised, and
tampering (including version and salt bytes) is detected.
"""

import os

from shield.core import (
    Shield,
    quick_encrypt,
    quick_decrypt,
    PBKDF2_ITERATIONS,
    VERSION_PASSWORD,
    VERSION_KEY,
    SALT_SIZE,
)


def test_same_password_service_different_keys():
    """Two instances with the same password+service get DIFFERENT keys.

    This is the high-severity fix: a random per-instance salt means the
    embedded salts differ and the derived keys differ.
    """
    pw, svc = "hunter2", "github.com"
    a = Shield(pw, svc)
    b = Shield(pw, svc)

    msg = b"identical plaintext"
    ca = a.encrypt(msg)
    cb = b.encrypt(msg)

    # Salts live at bytes [2:18] of a v4 password-mode ciphertext
    # (after version(1) + suite(1)).
    salt_a = ca[2:2 + SALT_SIZE]
    salt_b = cb[2:2 + SALT_SIZE]
    assert salt_a != salt_b

    # And the derived master keys differ (proves the deterministic-key bug
    # is gone, not just the salt).
    assert a.key != b.key


def test_cross_instance_roundtrip():
    """Bob (same password+service, different instance salt) decrypts Alice."""
    pw, svc = "correct horse battery staple", "service.example"
    alice = Shield(pw, svc)
    bob = Shield(pw, svc)

    msg = b"hello from alice"
    assert bob.decrypt(alice.encrypt(msg)) == msg


def test_same_instance_roundtrip():
    """Encrypt then decrypt on the same instance returns the plaintext."""
    s = Shield("pw", "svc")
    msg = b"round trip me"
    assert s.decrypt(s.encrypt(msg)) == msg


def test_tamper_detection():
    """Flipping ANY byte (version, salt, nonce, ct, mac) fails auth."""
    s = Shield("pw", "svc")
    ct = s.encrypt(b"secret payload")

    # Sanity: untampered decrypts.
    assert s.decrypt(ct) == b"secret payload"

    for i in range(len(ct)):
        tampered = ct[:i] + bytes([ct[i] ^ 0xFF]) + ct[i + 1:]
        assert s.decrypt(tampered) is None, f"tamper at byte {i} not detected"

    # Explicitly check the version byte (index 0) and a salt byte (index 1).
    flip_version = bytes([ct[0] ^ 0xFF]) + ct[1:]
    assert s.decrypt(flip_version) is None
    flip_salt = ct[:1] + bytes([ct[1] ^ 0xFF]) + ct[2:]
    assert s.decrypt(flip_salt) is None


def test_version_bytes():
    """Password ciphertext starts with 0x03; key/quick ciphertext with 0x13."""
    pw_ct = Shield("pw", "svc").encrypt(b"x")
    assert pw_ct[0] == VERSION_PASSWORD == 0x03

    key = os.urandom(32)
    quick_ct = quick_encrypt(key, b"x")
    assert quick_ct[0] == VERSION_KEY == 0x13

    keyed_ct = Shield.with_key(key).encrypt(b"x")
    assert keyed_ct[0] == VERSION_KEY == 0x13


def test_iterations_600k():
    """CR-2: PBKDF2 iteration count is 600,000."""
    assert PBKDF2_ITERATIONS == 600_000


def test_quick_key_roundtrip():
    """Pre-shared-key one-shot encrypt/decrypt round-trips."""
    key = os.urandom(32)
    msg = b"pre-shared key message"
    assert quick_decrypt(key, quick_encrypt(key, msg)) == msg

    # Wrong key fails.
    assert quick_decrypt(os.urandom(32), quick_encrypt(key, msg)) is None


def test_explicit_salt_is_honored_and_stored():
    """Passing salt= pins it and it is stored in the header."""
    salt = os.urandom(SALT_SIZE)
    a = Shield("pw", "svc", salt=salt)
    b = Shield("pw", "svc", salt=salt)
    assert a.key == b.key  # same salt -> same key

    ct = a.encrypt(b"data")
    assert ct[2:2 + SALT_SIZE] == salt
    assert b.decrypt(ct) == b"data"
