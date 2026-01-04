"""Tests for Shield key exchange."""

import os
import pytest
from shield.exchange import PAKEExchange, QRExchange, KeySplitter


class TestPAKEExchange:
    """Test PAKEExchange class."""

    def test_same_password_same_key(self):
        """Same password produces compatible keys."""
        salt = PAKEExchange.generate_salt()
        alice = PAKEExchange.derive("shared_secret", salt, "alice")
        bob = PAKEExchange.derive("shared_secret", salt, "bob")

        # Combined key should be the same
        key1 = PAKEExchange.combine(alice, bob)
        key2 = PAKEExchange.combine(bob, alice)
        assert key1 == key2

    def test_different_passwords(self):
        """Different passwords produce different keys."""
        salt = PAKEExchange.generate_salt()
        alice1 = PAKEExchange.derive("password1", salt, "alice")
        alice2 = PAKEExchange.derive("password2", salt, "alice")
        assert alice1 != alice2

    def test_different_roles(self):
        """Different roles produce different contributions."""
        salt = PAKEExchange.generate_salt()
        alice = PAKEExchange.derive("password", salt, "alice")
        bob = PAKEExchange.derive("password", salt, "bob")
        assert alice != bob

    def test_generate_salt(self):
        """Salt generation produces random bytes."""
        salt1 = PAKEExchange.generate_salt()
        salt2 = PAKEExchange.generate_salt()
        assert salt1 != salt2
        assert len(salt1) == 16


class TestQRExchange:
    """Test QRExchange class."""

    def test_encode_decode(self):
        """Encode and decode key."""
        key = os.urandom(32)
        encoded = QRExchange.encode(key)
        decoded = QRExchange.decode(encoded)
        assert decoded == key

    def test_url_safe(self):
        """Encoded key is URL-safe."""
        key = os.urandom(32)
        encoded = QRExchange.encode(key)
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=" for c in encoded)

    def test_exchange_data(self):
        """Generate and parse exchange data."""
        key = os.urandom(32)
        metadata = {"issuer": "MyApp", "expiry": 3600}
        data = QRExchange.generate_exchange_data(key, metadata)
        parsed_key, parsed_meta = QRExchange.parse_exchange_data(data)
        assert parsed_key == key
        assert parsed_meta == metadata

    def test_exchange_data_no_metadata(self):
        """Exchange data without metadata."""
        key = os.urandom(32)
        data = QRExchange.generate_exchange_data(key)
        parsed_key, parsed_meta = QRExchange.parse_exchange_data(data)
        assert parsed_key == key
        assert parsed_meta is None


class TestKeySplitter:
    """Test KeySplitter class."""

    def test_split_combine(self):
        """Split and combine key."""
        key = os.urandom(32)
        shares = KeySplitter.split(key, 3)
        recovered = KeySplitter.combine(shares)
        assert recovered == key

    def test_all_shares_required(self):
        """All shares needed for reconstruction."""
        key = os.urandom(32)
        shares = KeySplitter.split(key, 3)
        # Missing one share gives wrong key
        recovered = KeySplitter.combine(shares[:2])
        assert recovered != key

    def test_minimum_shares(self):
        """Need at least 2 shares."""
        key = os.urandom(32)
        with pytest.raises(ValueError):
            KeySplitter.split(key, 1)

    def test_different_share_counts(self):
        """Various share counts work."""
        key = os.urandom(32)
        for n in [2, 3, 5, 10]:
            shares = KeySplitter.split(key, n)
            assert len(shares) == n
            recovered = KeySplitter.combine(shares)
            assert recovered == key

    def test_shares_are_random(self):
        """Shares are random, not deterministic."""
        key = os.urandom(32)
        shares1 = KeySplitter.split(key, 3)
        shares2 = KeySplitter.split(key, 3)
        # At least one share should differ
        assert any(s1 != s2 for s1, s2 in zip(shares1, shares2))
