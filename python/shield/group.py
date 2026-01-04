"""
Shield Group Encryption - Multi-recipient encryption.

Encrypt once for multiple recipients, each can decrypt with their own key.

Example:
    >>> from shield.group import GroupEncryption
    >>>
    >>> group = GroupEncryption()
    >>> group.add_member("alice", alice_shared_key)
    >>> group.add_member("bob", bob_shared_key)
    >>>
    >>> encrypted = group.encrypt(b"group message")
    >>>
    >>> # Each member decrypts with their key
    >>> decrypted = GroupEncryption.decrypt(encrypted, "alice", alice_shared_key)
"""

import os
import hmac
import hashlib
import struct
import secrets
import json
import base64
from typing import Dict, Optional, List


def _generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate keystream using SHA256."""
    keystream = b""
    for i in range((length + 31) // 32):
        keystream += hashlib.sha256(key + nonce + struct.pack("<I", i)).digest()
    return keystream[:length]


def _encrypt_block(key: bytes, data: bytes) -> bytes:
    """Encrypt a block with HMAC authentication."""
    nonce = os.urandom(16)
    keystream = _generate_keystream(key, nonce, len(data))
    ciphertext = bytes(a ^ b for a, b in zip(data, keystream))
    mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:16]
    return nonce + ciphertext + mac


def _decrypt_block(key: bytes, encrypted: bytes) -> Optional[bytes]:
    """Decrypt a block with HMAC verification."""
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


class GroupEncryption:
    """
    Multi-recipient encryption.

    Uses a group key for message encryption, then encrypts
    the group key separately for each member.
    """

    def __init__(self, group_key: bytes = None):
        """
        Initialize group encryption.

        Args:
            group_key: 32-byte group key (generated if not provided)
        """
        self.group_key = group_key or secrets.token_bytes(32)
        self._members: Dict[str, bytes] = {}

    def add_member(self, member_id: str, shared_key: bytes) -> None:
        """
        Add a member to the group.

        Args:
            member_id: Unique member identifier
            shared_key: Pre-shared key with this member
        """
        self._members[member_id] = shared_key

    def remove_member(self, member_id: str) -> bool:
        """
        Remove a member from the group.

        Note: After removing a member, you should rotate the group key.

        Args:
            member_id: Member to remove

        Returns:
            True if member was removed
        """
        if member_id in self._members:
            del self._members[member_id]
            return True
        return False

    @property
    def members(self) -> List[str]:
        """Get list of member IDs."""
        return list(self._members.keys())

    def encrypt(self, plaintext: bytes) -> dict:
        """
        Encrypt for all group members.

        Args:
            plaintext: Message to encrypt

        Returns:
            Dictionary with ciphertext and per-member encrypted keys
        """
        # Encrypt message with group key
        ciphertext = _encrypt_block(self.group_key, plaintext)

        # Encrypt group key for each member
        encrypted_keys = {}
        for member_id, member_key in self._members.items():
            encrypted_keys[member_id] = base64.b64encode(
                _encrypt_block(member_key, self.group_key)
            ).decode('ascii')

        return {
            'version': 1,
            'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
            'keys': encrypted_keys
        }

    @staticmethod
    def decrypt(encrypted: dict, member_id: str, member_key: bytes) -> Optional[bytes]:
        """
        Decrypt as a group member.

        Args:
            encrypted: Encrypted message from encrypt()
            member_id: Your member ID
            member_key: Your shared key

        Returns:
            Decrypted message, or None if decryption fails
        """
        if member_id not in encrypted.get('keys', {}):
            return None

        # Decrypt group key
        encrypted_group_key = base64.b64decode(encrypted['keys'][member_id])
        group_key = _decrypt_block(member_key, encrypted_group_key)
        if group_key is None:
            return None

        # Decrypt message
        ciphertext = base64.b64decode(encrypted['ciphertext'])
        return _decrypt_block(group_key, ciphertext)

    def rotate_key(self) -> bytes:
        """
        Rotate the group key.

        Returns:
            New group key
        """
        old_key = self.group_key
        self.group_key = secrets.token_bytes(32)
        return old_key

    def to_json(self) -> str:
        """Serialize encrypted message to JSON string."""
        # This is for the encrypt() result, not the group itself
        pass

    @staticmethod
    def from_json(json_str: str) -> dict:
        """Parse encrypted message from JSON string."""
        return json.loads(json_str)


class BroadcastEncryption:
    """
    Efficient broadcast encryption for large groups.

    Uses a key hierarchy to reduce per-message overhead.
    Members are organized into subgroups with shared subgroup keys.
    """

    def __init__(self, master_key: bytes = None, subgroup_size: int = 16):
        """
        Initialize broadcast encryption.

        Args:
            master_key: Master key for the broadcast
            subgroup_size: Members per subgroup
        """
        self.master_key = master_key or secrets.token_bytes(32)
        self.subgroup_size = subgroup_size
        self._members: Dict[str, Tuple] = {}  # member_id -> (subgroup_id, member_key)
        self._subgroup_keys: Dict[int, bytes] = {}
        self._next_subgroup = 0

    def add_member(self, member_id: str, member_key: bytes) -> int:
        """
        Add member to broadcast group.

        Args:
            member_id: Unique member ID
            member_key: Shared key with member

        Returns:
            Subgroup ID assigned
        """
        # Find subgroup with space
        subgroup_id = None
        for sg_id, sg_key in self._subgroup_keys.items():
            members_in_sg = sum(1 for m in self._members.values() if m[0] == sg_id)
            if members_in_sg < self.subgroup_size:
                subgroup_id = sg_id
                break

        if subgroup_id is None:
            subgroup_id = self._next_subgroup
            self._subgroup_keys[subgroup_id] = secrets.token_bytes(32)
            self._next_subgroup += 1

        self._members[member_id] = (subgroup_id, member_key)
        return subgroup_id

    def encrypt(self, plaintext: bytes) -> dict:
        """
        Encrypt for broadcast.

        Uses two-level encryption:
        1. Message encrypted with message key
        2. Message key encrypted with each subgroup key
        3. Subgroup keys encrypted with member keys

        Returns:
            Encrypted broadcast message
        """
        message_key = secrets.token_bytes(32)

        # Encrypt message
        ciphertext = _encrypt_block(message_key, plaintext)

        # Encrypt message key for each subgroup
        subgroup_keys_enc = {}
        for sg_id, sg_key in self._subgroup_keys.items():
            subgroup_keys_enc[str(sg_id)] = base64.b64encode(
                _encrypt_block(sg_key, message_key)
            ).decode('ascii')

        # Encrypt subgroup keys for each member
        member_keys_enc = {}
        for member_id, (sg_id, member_key) in self._members.items():
            sg_key = self._subgroup_keys[sg_id]
            member_keys_enc[member_id] = {
                'sg': sg_id,
                'key': base64.b64encode(_encrypt_block(member_key, sg_key)).decode('ascii')
            }

        return {
            'version': 1,
            'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
            'subgroups': subgroup_keys_enc,
            'members': member_keys_enc
        }

    @staticmethod
    def decrypt(encrypted: dict, member_id: str, member_key: bytes) -> Optional[bytes]:
        """
        Decrypt broadcast as member.

        Args:
            encrypted: Encrypted broadcast
            member_id: Your member ID
            member_key: Your shared key

        Returns:
            Decrypted message
        """
        if member_id not in encrypted.get('members', {}):
            return None

        member_data = encrypted['members'][member_id]
        sg_id = member_data['sg']

        # Decrypt subgroup key
        sg_key_enc = base64.b64decode(member_data['key'])
        sg_key = _decrypt_block(member_key, sg_key_enc)
        if sg_key is None:
            return None

        # Decrypt message key
        msg_key_enc = base64.b64decode(encrypted['subgroups'][str(sg_id)])
        msg_key = _decrypt_block(sg_key, msg_key_enc)
        if msg_key is None:
            return None

        # Decrypt message
        ciphertext = base64.b64decode(encrypted['ciphertext'])
        return _decrypt_block(msg_key, ciphertext)
