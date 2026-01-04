"""Tests for Shield identity/SSO."""

import os
import time
import pytest
from shield.identity import IdentityProvider, Identity, SecureSession


class TestIdentityProvider:
    """Test IdentityProvider class."""

    def test_register_user(self):
        """Register new user."""
        provider = IdentityProvider(os.urandom(32))
        identity = provider.register("alice", "password123", "Alice Smith")

        assert identity.user_id == "alice"
        assert identity.display_name == "Alice Smith"
        assert len(identity.verification_key) == 32

    def test_register_duplicate_fails(self):
        """Cannot register duplicate user."""
        provider = IdentityProvider(os.urandom(32))
        provider.register("alice", "password", "Alice")

        with pytest.raises(ValueError, match="already exists"):
            provider.register("alice", "password2", "Alice 2")

    def test_authenticate_success(self):
        """Successful authentication returns token."""
        provider = IdentityProvider(os.urandom(32))
        provider.register("alice", "password123", "Alice")

        token = provider.authenticate("alice", "password123")
        assert token is not None

    def test_authenticate_wrong_password(self):
        """Wrong password returns None."""
        provider = IdentityProvider(os.urandom(32))
        provider.register("alice", "password123", "Alice")

        token = provider.authenticate("alice", "wrongpassword")
        assert token is None

    def test_authenticate_unknown_user(self):
        """Unknown user returns None."""
        provider = IdentityProvider(os.urandom(32))
        token = provider.authenticate("nobody", "password")
        assert token is None

    def test_validate_token(self):
        """Validate session token."""
        provider = IdentityProvider(os.urandom(32))
        provider.register("alice", "password", "Alice")
        token = provider.authenticate("alice", "password")

        session = provider.validate_token(token)
        assert session is not None
        assert session.user_id == "alice"
        assert not session.is_expired

    def test_expired_token(self):
        """Expired token is rejected."""
        provider = IdentityProvider(os.urandom(32), token_ttl=1)
        provider.register("alice", "password", "Alice")
        token = provider.authenticate("alice", "password")

        # Wait for expiry (need to wait slightly longer than TTL)
        time.sleep(2)

        session = provider.validate_token(token)
        assert session is None

    def test_tampered_token(self):
        """Tampered token is rejected."""
        provider = IdentityProvider(os.urandom(32))
        provider.register("alice", "password", "Alice")
        token = provider.authenticate("alice", "password")

        # Tamper with token
        import base64
        decoded = bytearray(base64.urlsafe_b64decode(token))
        decoded[10] ^= 0xFF
        tampered = base64.urlsafe_b64encode(bytes(decoded)).decode()

        session = provider.validate_token(tampered)
        assert session is None

    def test_service_token(self):
        """Create and validate service token."""
        provider = IdentityProvider(os.urandom(32))
        provider.register("alice", "password", "Alice")
        session_token = provider.authenticate("alice", "password")

        service_token = provider.create_service_token(
            session_token,
            "api.example.com",
            permissions=["read", "write"]
        )

        session = provider.validate_service_token(service_token, "api.example.com")
        assert session is not None
        assert session.user_id == "alice"
        assert "read" in session.permissions

    def test_service_token_wrong_service(self):
        """Service token rejected for wrong service."""
        provider = IdentityProvider(os.urandom(32))
        provider.register("alice", "password", "Alice")
        session_token = provider.authenticate("alice", "password")

        service_token = provider.create_service_token(session_token, "api.example.com")

        session = provider.validate_service_token(service_token, "other.example.com")
        assert session is None

    def test_refresh_token(self):
        """Refresh session token."""
        provider = IdentityProvider(os.urandom(32))
        provider.register("alice", "password", "Alice")
        token1 = provider.authenticate("alice", "password")

        token2 = provider.refresh_token(token1)
        assert token2 is not None
        assert token2 != token1

        session = provider.validate_token(token2)
        assert session.user_id == "alice"

    def test_revoke_user(self):
        """Revoke user identity."""
        provider = IdentityProvider(os.urandom(32))
        provider.register("alice", "password", "Alice")

        assert provider.get_identity("alice") is not None
        provider.revoke_user("alice")
        assert provider.get_identity("alice") is None

    def test_permissions_in_token(self):
        """Permissions included in token."""
        provider = IdentityProvider(os.urandom(32))
        provider.register("alice", "password", "Alice")

        token = provider.authenticate("alice", "password", permissions=["admin", "user"])
        session = provider.validate_token(token)

        assert "admin" in session.permissions
        assert "user" in session.permissions


class TestSecureSession:
    """Test SecureSession class."""

    def test_encrypt_decrypt(self):
        """Basic encrypt/decrypt."""
        session = SecureSession(os.urandom(32))
        plaintext = b"session data"
        encrypted = session.encrypt(plaintext)
        decrypted = session.decrypt(encrypted)
        assert decrypted == plaintext

    def test_auto_rotation(self):
        """Key auto-rotates after interval."""
        session = SecureSession(
            os.urandom(32),
            rotation_interval=1,
            max_old_keys=2
        )

        # Encrypt before rotation
        enc1 = session.encrypt(b"message 1")
        version1 = session._key_version

        # Wait for rotation
        time.sleep(1.5)

        # Encrypt after rotation
        enc2 = session.encrypt(b"message 2")
        version2 = session._key_version

        assert version2 > version1

        # Both still decrypt
        assert session.decrypt(enc1) == b"message 1"
        assert session.decrypt(enc2) == b"message 2"

    def test_tampered_data_fails(self):
        """Tampered data fails decryption."""
        session = SecureSession(os.urandom(32))
        encrypted = bytearray(session.encrypt(b"data"))
        encrypted[20] ^= 0xFF

        result = session.decrypt(bytes(encrypted))
        assert result is None
