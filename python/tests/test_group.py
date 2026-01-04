"""Tests for Shield group encryption."""

import os
import pytest
from shield.group import GroupEncryption, BroadcastEncryption


class TestGroupEncryption:
    """Test GroupEncryption class."""

    def test_basic_encryption(self):
        """Basic group encryption."""
        alice_key = os.urandom(32)
        bob_key = os.urandom(32)

        group = GroupEncryption()
        group.add_member("alice", alice_key)
        group.add_member("bob", bob_key)

        encrypted = group.encrypt(b"group message")

        # Both can decrypt
        dec_alice = GroupEncryption.decrypt(encrypted, "alice", alice_key)
        dec_bob = GroupEncryption.decrypt(encrypted, "bob", bob_key)

        assert dec_alice == b"group message"
        assert dec_bob == b"group message"

    def test_non_member_cannot_decrypt(self):
        """Non-member cannot decrypt."""
        group = GroupEncryption()
        group.add_member("alice", os.urandom(32))

        encrypted = group.encrypt(b"secret")

        # Eve not in group
        result = GroupEncryption.decrypt(encrypted, "eve", os.urandom(32))
        assert result is None

    def test_wrong_key_fails(self):
        """Wrong key fails decryption."""
        alice_key = os.urandom(32)
        group = GroupEncryption()
        group.add_member("alice", alice_key)

        encrypted = group.encrypt(b"secret")

        # Wrong key
        result = GroupEncryption.decrypt(encrypted, "alice", os.urandom(32))
        assert result is None

    def test_remove_member(self):
        """Remove member from group."""
        alice_key = os.urandom(32)
        group = GroupEncryption()
        group.add_member("alice", alice_key)
        group.add_member("bob", os.urandom(32))

        assert "alice" in group.members
        group.remove_member("alice")
        assert "alice" not in group.members

    def test_rotate_key(self):
        """Rotate group key."""
        group = GroupEncryption()
        old_key = group.group_key
        new_key = group.rotate_key()

        assert new_key == old_key
        assert group.group_key != old_key

    def test_custom_group_key(self):
        """Use custom group key."""
        custom_key = os.urandom(32)
        group = GroupEncryption(group_key=custom_key)
        assert group.group_key == custom_key


class TestBroadcastEncryption:
    """Test BroadcastEncryption class."""

    def test_basic_broadcast(self):
        """Basic broadcast encryption."""
        broadcast = BroadcastEncryption()

        alice_key = os.urandom(32)
        bob_key = os.urandom(32)
        charlie_key = os.urandom(32)

        broadcast.add_member("alice", alice_key)
        broadcast.add_member("bob", bob_key)
        broadcast.add_member("charlie", charlie_key)

        encrypted = broadcast.encrypt(b"broadcast message")

        # All can decrypt
        assert BroadcastEncryption.decrypt(encrypted, "alice", alice_key) == b"broadcast message"
        assert BroadcastEncryption.decrypt(encrypted, "bob", bob_key) == b"broadcast message"
        assert BroadcastEncryption.decrypt(encrypted, "charlie", charlie_key) == b"broadcast message"

    def test_non_member_cannot_decrypt(self):
        """Non-member cannot decrypt broadcast."""
        broadcast = BroadcastEncryption()
        broadcast.add_member("alice", os.urandom(32))

        encrypted = broadcast.encrypt(b"secret")

        result = BroadcastEncryption.decrypt(encrypted, "eve", os.urandom(32))
        assert result is None

    def test_subgroup_assignment(self):
        """Members are assigned to subgroups."""
        broadcast = BroadcastEncryption(subgroup_size=2)

        sg1 = broadcast.add_member("m1", os.urandom(32))
        sg2 = broadcast.add_member("m2", os.urandom(32))
        sg3 = broadcast.add_member("m3", os.urandom(32))

        # First two in subgroup 0, third in subgroup 1
        assert sg1 == 0
        assert sg2 == 0
        assert sg3 == 1

    def test_large_group(self):
        """Large group with multiple subgroups."""
        broadcast = BroadcastEncryption(subgroup_size=5)

        keys = {}
        for i in range(25):
            member_id = f"member_{i}"
            keys[member_id] = os.urandom(32)
            broadcast.add_member(member_id, keys[member_id])

        encrypted = broadcast.encrypt(b"large group message")

        # All can decrypt
        for member_id, key in keys.items():
            result = BroadcastEncryption.decrypt(encrypted, member_id, key)
            assert result == b"large group message"
