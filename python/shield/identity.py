"""
Shield Identity - SSO/Identity Provider without public-key crypto.

Provides user registration, session management, and service tokens
using only symmetric cryptography.

Example:
    >>> from shield.identity import IdentityProvider
    >>>
    >>> provider = IdentityProvider(provider_key)
    >>> identity = provider.register("alice", "password123", "Alice Smith")
    >>> token = provider.authenticate("alice", "password123")
    >>> session = provider.validate_token(token)
"""

import hmac
import hashlib
import struct
import time
import secrets
import json
import base64
from typing import Optional, Dict, List
from dataclasses import dataclass, field, asdict


@dataclass
class Identity:
    """User identity."""
    user_id: str
    display_name: str
    verification_key: bytes
    created_at: int = field(default_factory=lambda: int(time.time()))
    attributes: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary (for storage)."""
        return {
            'user_id': self.user_id,
            'display_name': self.display_name,
            'verification_key': base64.b64encode(self.verification_key).decode(),
            'created_at': self.created_at,
            'attributes': self.attributes
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Identity':
        """Create from dictionary."""
        return cls(
            user_id=data['user_id'],
            display_name=data['display_name'],
            verification_key=base64.b64decode(data['verification_key']),
            created_at=data['created_at'],
            attributes=data.get('attributes', {})
        )


@dataclass
class Session:
    """Session information from validated token."""
    user_id: str
    created: int
    expires: int
    permissions: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        """Check if session is expired."""
        return time.time() > self.expires

    @property
    def remaining_time(self) -> int:
        """Seconds until expiration."""
        return max(0, self.expires - int(time.time()))


class IdentityProvider:
    """
    SSO Identity Provider using symmetric crypto.

    All tokens are HMAC-signed with the provider key.
    No public-key certificates required.
    """

    def __init__(self, provider_key: bytes, token_ttl: int = 3600):
        """
        Initialize identity provider.

        Args:
            provider_key: 32-byte provider secret key
            token_ttl: Default token lifetime in seconds
        """
        self.provider_key = provider_key
        self.token_ttl = token_ttl
        self._identities: Dict[str, Identity] = {}

    def register(
        self,
        user_id: str,
        password: str,
        display_name: str,
        attributes: Dict = None
    ) -> Identity:
        """
        Register new user identity.

        Args:
            user_id: Unique user identifier
            password: User's password
            display_name: User's display name
            attributes: Optional user attributes

        Returns:
            Created identity

        Raises:
            ValueError: If user_id already exists
        """
        if user_id in self._identities:
            raise ValueError(f"User {user_id} already exists")

        # Derive user's verification key from password
        salt = hashlib.sha256(f"user:{user_id}".encode()).digest()
        user_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        verification_key = hashlib.sha256(b'verify:' + user_key).digest()

        identity = Identity(
            user_id=user_id,
            display_name=display_name,
            verification_key=verification_key,
            attributes=attributes or {}
        )

        self._identities[user_id] = identity
        return identity

    def authenticate(
        self,
        user_id: str,
        password: str,
        permissions: List[str] = None,
        ttl: int = None
    ) -> Optional[str]:
        """
        Authenticate user and return session token.

        Args:
            user_id: User identifier
            password: User's password
            permissions: Optional permission list
            ttl: Token lifetime (default: provider default)

        Returns:
            Session token, or None if authentication fails
        """
        if user_id not in self._identities:
            return None

        identity = self._identities[user_id]

        # Verify password
        salt = hashlib.sha256(f"user:{user_id}".encode()).digest()
        user_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        verification_key = hashlib.sha256(b'verify:' + user_key).digest()

        if not hmac.compare_digest(verification_key, identity.verification_key):
            return None

        # Create session token
        ttl = ttl or self.token_ttl
        session_data = {
            'user_id': user_id,
            'created': int(time.time()),
            'expires': int(time.time()) + ttl,
            'permissions': permissions or [],
            'nonce': secrets.token_hex(8)
        }

        return self._sign_token(session_data)

    def validate_token(self, token: str) -> Optional[Session]:
        """
        Validate session token.

        Args:
            token: Session token from authenticate()

        Returns:
            Session object, or None if invalid/expired
        """
        session_data = self._verify_token(token)
        if session_data is None:
            return None

        # Check expiry
        if session_data['expires'] < int(time.time()):
            return None

        return Session(
            user_id=session_data['user_id'],
            created=session_data['created'],
            expires=session_data['expires'],
            permissions=session_data.get('permissions', []),
            metadata=session_data.get('metadata', {})
        )

    def create_service_token(
        self,
        session_token: str,
        service: str,
        permissions: List[str] = None,
        ttl: int = 300
    ) -> Optional[str]:
        """
        Create service-specific access token.

        Args:
            session_token: Valid session token
            service: Target service identifier
            permissions: Scoped permissions for this service
            ttl: Token lifetime (shorter than session)

        Returns:
            Service token, or None if session invalid
        """
        session = self.validate_token(session_token)
        if session is None:
            return None

        # Create scoped service token
        service_data = {
            'user_id': session.user_id,
            'service': service,
            'created': int(time.time()),
            'expires': int(time.time()) + ttl,
            'permissions': permissions or [],
            'parent_expires': session.expires
        }

        return self._sign_token(service_data)

    def validate_service_token(self, token: str, service: str) -> Optional[Session]:
        """
        Validate service-specific token.

        Args:
            token: Service token
            service: Expected service identifier

        Returns:
            Session object, or None if invalid
        """
        token_data = self._verify_token(token)
        if token_data is None:
            return None

        # Verify service match
        if token_data.get('service') != service:
            return None

        # Check expiry
        now = int(time.time())
        if token_data['expires'] < now:
            return None
        if token_data.get('parent_expires', now + 1) < now:
            return None

        return Session(
            user_id=token_data['user_id'],
            created=token_data['created'],
            expires=token_data['expires'],
            permissions=token_data.get('permissions', []),
            metadata={'service': service}
        )

    def refresh_token(self, token: str, ttl: int = None) -> Optional[str]:
        """
        Refresh session token.

        Args:
            token: Current valid session token
            ttl: New lifetime (default: provider default)

        Returns:
            New session token, or None if current token invalid
        """
        session = self.validate_token(token)
        if session is None:
            return None

        ttl = ttl or self.token_ttl
        session_data = {
            'user_id': session.user_id,
            'created': int(time.time()),
            'expires': int(time.time()) + ttl,
            'permissions': session.permissions,
            'nonce': secrets.token_hex(8)
        }

        return self._sign_token(session_data)

    def revoke_user(self, user_id: str) -> bool:
        """
        Revoke user identity.

        Note: This doesn't invalidate existing tokens immediately.
        For immediate revocation, maintain a revocation list.

        Args:
            user_id: User to revoke

        Returns:
            True if user was revoked
        """
        if user_id in self._identities:
            del self._identities[user_id]
            return True
        return False

    def get_identity(self, user_id: str) -> Optional[Identity]:
        """Get identity by user ID."""
        return self._identities.get(user_id)

    def _sign_token(self, data: dict) -> str:
        """Sign token data."""
        token_bytes = json.dumps(data, separators=(',', ':')).encode()
        mac = hmac.new(self.provider_key, token_bytes, hashlib.sha256).digest()[:16]
        return base64.urlsafe_b64encode(token_bytes + mac).decode()

    def _verify_token(self, token: str) -> Optional[dict]:
        """Verify and parse token."""
        try:
            decoded = base64.urlsafe_b64decode(token)
            if len(decoded) < 17:
                return None

            token_bytes = decoded[:-16]
            mac = decoded[-16:]

            expected_mac = hmac.new(
                self.provider_key,
                token_bytes,
                hashlib.sha256
            ).digest()[:16]

            if not hmac.compare_digest(mac, expected_mac):
                return None

            return json.loads(token_bytes)
        except Exception:
            return None


class SecureSession:
    """
    Session with automatic key rotation.

    Rotates encryption key periodically while maintaining
    backward compatibility for decryption.
    """

    def __init__(
        self,
        session_key: bytes,
        rotation_interval: int = 3600,
        max_old_keys: int = 3
    ):
        """
        Initialize secure session.

        Args:
            session_key: Initial session key
            rotation_interval: Seconds between rotations
            max_old_keys: Number of old keys to keep
        """
        self._current_key = session_key
        self._old_keys: List[bytes] = []
        self._rotation_interval = rotation_interval
        self._max_old_keys = max_old_keys
        self._last_rotation = int(time.time())
        self._key_version = 0

    def _maybe_rotate(self) -> bool:
        """Rotate key if needed."""
        now = int(time.time())
        if now - self._last_rotation >= self._rotation_interval:
            # Save old key
            self._old_keys.append(self._current_key)
            if len(self._old_keys) > self._max_old_keys:
                self._old_keys.pop(0)

            # Generate new key
            self._current_key = hashlib.sha256(
                self._current_key + struct.pack('<Q', now)
            ).digest()
            self._last_rotation = now
            self._key_version += 1
            return True
        return False

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt with current key (auto-rotates if needed)."""
        self._maybe_rotate()

        version = struct.pack('<I', self._key_version)
        nonce = secrets.token_bytes(16)

        # Simple XOR cipher with SHA256 keystream
        keystream = b''
        for i in range((len(data) + 31) // 32):
            keystream += hashlib.sha256(
                self._current_key + nonce + struct.pack('<I', i)
            ).digest()

        ciphertext = bytes(a ^ b for a, b in zip(data, keystream[:len(data)]))
        mac = hmac.new(
            self._current_key,
            version + nonce + ciphertext,
            hashlib.sha256
        ).digest()[:16]

        return version + nonce + ciphertext + mac

    def decrypt(self, encrypted: bytes) -> Optional[bytes]:
        """Decrypt with appropriate key version."""
        self._maybe_rotate()

        if len(encrypted) < 36:
            return None

        version = struct.unpack('<I', encrypted[:4])[0]
        nonce = encrypted[4:20]
        ciphertext = encrypted[20:-16]
        mac = encrypted[-16:]

        # Find appropriate key
        if version == self._key_version:
            key = self._current_key
        elif version < self._key_version:
            key_index = self._key_version - version - 1
            if key_index >= len(self._old_keys):
                return None
            key = self._old_keys[-(key_index + 1)]
        else:
            return None

        # Verify MAC
        expected_mac = hmac.new(
            key,
            encrypted[:-16],
            hashlib.sha256
        ).digest()[:16]

        if not hmac.compare_digest(mac, expected_mac):
            return None

        # Decrypt
        keystream = b''
        for i in range((len(ciphertext) + 31) // 32):
            keystream += hashlib.sha256(
                key + nonce + struct.pack('<I', i)
            ).digest()

        return bytes(a ^ b for a, b in zip(ciphertext, keystream[:len(ciphertext)]))
