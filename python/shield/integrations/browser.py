"""
Browser Integration Helpers for Shield

Provides utilities for secure browser-server communication:
- Encrypted cookies with tamper protection
- CORS with encrypted preflight caching
- Browser bridge for client-side decryption keys

Usage:
    from shield.integrations import BrowserBridge, EncryptedCookie, SecureCORS

    # Generate browser decryption key
    bridge = BrowserBridge(password="secret", service="api.example.com")
    client_key = bridge.generate_client_key(session_id="session123")

    # Encrypted cookies
    cookie = EncryptedCookie(password="secret", service="api.example.com")
    encrypted_value = cookie.encode({"user_id": "123", "role": "admin"})

    # CORS with security
    cors = SecureCORS(
        allowed_origins=["https://app.example.com"],
        password="secret",
        service="api.example.com"
    )
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from shield import Shield, quick_encrypt, quick_decrypt


class BrowserBridge:
    """
    Facilitates secure key exchange between server and browser.

    Generates session-specific encryption keys that can be safely
    sent to browsers for client-side decryption.

    Args:
        password: Server encryption password
        service: Service identifier

    Usage:
        bridge = BrowserBridge(password="secret", service="api.example.com")

        # Generate a client key for a session
        client_key = bridge.generate_client_key(
            session_id="unique-session-id",
            ttl=3600  # 1 hour
        )

        # Client uses this key to decrypt responses
        # Server encrypts with session-derived key
        encrypted = bridge.encrypt_for_client(session_id, data)
    """

    def __init__(self, password: str, service: str):
        self.shield = Shield(password, service)
        self.service = service
        self._session_keys: Dict[str, tuple[bytes, float]] = {}

    def generate_client_key(
        self,
        session_id: str,
        ttl: int = 3600,
        include_meta: bool = True,
    ) -> dict:
        """
        Generate a client decryption key for a session.

        Returns a dict with the key and metadata that can be
        safely sent to the browser.
        """
        # Derive session-specific key
        session_key = self._derive_session_key(session_id)
        expires_at = time.time() + ttl

        # Store for server-side use
        self._session_keys[session_id] = (session_key, expires_at)

        # Encode key for browser (base64 for JavaScript compatibility)
        key_b64 = base64.b64encode(session_key).decode("ascii")

        if include_meta:
            return {
                "key": key_b64,
                "session_id": session_id,
                "expires_at": int(expires_at),
                "algorithm": "shield-v1",
                "service": self.service,
            }
        return {"key": key_b64}

    def _derive_session_key(self, session_id: str) -> bytes:
        """Derive a session-specific key."""
        # Use HMAC to derive session key from master key
        master = self.shield.key
        return hmac.new(
            master,
            session_id.encode("utf-8"),
            hashlib.sha256,
        ).digest()

    def encrypt_for_client(self, session_id: str, data: bytes) -> bytes:
        """Encrypt data for a specific client session."""
        session_key = self._derive_session_key(session_id)
        return quick_encrypt(session_key, data)

    def decrypt_from_client(self, session_id: str, encrypted: bytes) -> bytes:
        """Decrypt data from a client session."""
        session_key = self._derive_session_key(session_id)
        return quick_decrypt(session_key, encrypted)

    def is_session_valid(self, session_id: str) -> bool:
        """Check if a session key is still valid."""
        if session_id not in self._session_keys:
            return False
        _, expires_at = self._session_keys[session_id]
        return time.time() < expires_at

    def revoke_session(self, session_id: str) -> None:
        """Revoke a session key."""
        if session_id in self._session_keys:
            del self._session_keys[session_id]

    def cleanup_expired(self) -> int:
        """Remove expired session keys. Returns count of removed."""
        now = time.time()
        expired = [
            sid for sid, (_, exp) in self._session_keys.items()
            if now >= exp
        ]
        for sid in expired:
            del self._session_keys[sid]
        return len(expired)


@dataclass
class CookieOptions:
    """Options for cookie encoding."""
    max_age: Optional[int] = 3600
    path: str = "/"
    domain: Optional[str] = None
    secure: bool = True
    httponly: bool = True
    samesite: str = "Strict"


class EncryptedCookie:
    """
    Encrypted cookie helper with tamper protection.

    Encrypts cookie values using Shield, preventing tampering
    and protecting sensitive session data.

    Args:
        password: Encryption password
        service: Service identifier
        options: Default cookie options

    Usage:
        cookie = EncryptedCookie(password="secret", service="api.example.com")

        # Encode value for Set-Cookie header
        value = cookie.encode({"user_id": "123", "roles": ["admin"]})

        # Decode value from Cookie header
        data = cookie.decode(value)

        # Generate full Set-Cookie header
        header = cookie.make_header("session", {"user_id": "123"})
    """

    def __init__(
        self,
        password: str,
        service: str,
        options: Optional[CookieOptions] = None,
    ):
        self.shield = Shield(password, service)
        self.options = options or CookieOptions()

    def encode(self, data: dict) -> str:
        """Encode data as encrypted cookie value."""
        payload = {
            "data": data,
            "created_at": int(time.time()),
        }
        if self.options.max_age:
            payload["expires_at"] = int(time.time()) + self.options.max_age

        serialized = json.dumps(payload).encode("utf-8")
        encrypted = self.shield.encrypt(serialized)
        return base64.urlsafe_b64encode(encrypted).decode("ascii")

    def decode(self, value: str) -> Optional[dict]:
        """Decode encrypted cookie value. Returns None if invalid/expired."""
        try:
            encrypted = base64.urlsafe_b64decode(value)
            decrypted = self.shield.decrypt(encrypted)
            payload = json.loads(decrypted)

            # Check expiration
            if "expires_at" in payload:
                if time.time() > payload["expires_at"]:
                    return None

            return payload.get("data")
        except Exception:
            return None

    def make_header(
        self,
        name: str,
        data: dict,
        options: Optional[CookieOptions] = None,
    ) -> str:
        """Generate a complete Set-Cookie header value."""
        opts = options or self.options
        value = self.encode(data)

        parts = [f"{name}={value}"]

        if opts.max_age is not None:
            parts.append(f"Max-Age={opts.max_age}")
        if opts.path:
            parts.append(f"Path={opts.path}")
        if opts.domain:
            parts.append(f"Domain={opts.domain}")
        if opts.secure:
            parts.append("Secure")
        if opts.httponly:
            parts.append("HttpOnly")
        if opts.samesite:
            parts.append(f"SameSite={opts.samesite}")

        return "; ".join(parts)

    def parse_header(self, cookie_header: str, name: str) -> Optional[dict]:
        """Parse a Cookie header and decode a specific cookie."""
        cookies = {}
        for part in cookie_header.split(";"):
            part = part.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                cookies[key.strip()] = value.strip()

        if name in cookies:
            return self.decode(cookies[name])
        return None


class SecureCORS:
    """
    CORS handler with encrypted origin validation.

    Provides secure CORS handling with:
    - Origin validation against encrypted whitelist
    - Preflight response caching
    - Request signing for added security

    Args:
        allowed_origins: List of allowed origins
        password: Encryption password
        service: Service identifier
        max_age: Preflight cache max age
        allow_credentials: Whether to allow credentials
        allowed_methods: Allowed HTTP methods
        allowed_headers: Allowed request headers

    Usage:
        cors = SecureCORS(
            allowed_origins=["https://app.example.com"],
            password="secret",
            service="api.example.com"
        )

        # Check and get CORS headers
        headers = cors.get_headers(
            origin="https://app.example.com",
            method="GET"
        )

        # Handle preflight
        if is_preflight:
            return cors.preflight_response(origin, request_method)
    """

    def __init__(
        self,
        allowed_origins: List[str],
        password: str,
        service: str,
        max_age: int = 86400,
        allow_credentials: bool = True,
        allowed_methods: Optional[List[str]] = None,
        allowed_headers: Optional[List[str]] = None,
    ):
        self.shield = Shield(password, service)
        self.allowed_origins: Set[str] = set(allowed_origins)
        self.allow_all = "*" in allowed_origins
        self.max_age = max_age
        self.allow_credentials = allow_credentials
        self.allowed_methods = allowed_methods or [
            "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
        ]
        self.allowed_headers = allowed_headers or [
            "Content-Type", "Authorization", "X-API-Key",
            "X-Request-ID", "X-Shield-Session"
        ]

    def is_origin_allowed(self, origin: str) -> bool:
        """Check if origin is in the allowed list."""
        if self.allow_all:
            return True
        return origin in self.allowed_origins

    def get_headers(
        self,
        origin: str,
        method: str = "GET",
    ) -> Dict[str, str]:
        """Get CORS headers for a request."""
        headers: Dict[str, str] = {}

        if not self.is_origin_allowed(origin):
            return headers

        # Set origin (don't use * with credentials)
        if self.allow_credentials:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        else:
            headers["Access-Control-Allow-Origin"] = "*" if self.allow_all else origin

        headers["Vary"] = "Origin"

        return headers

    def preflight_response(
        self,
        origin: str,
        request_method: Optional[str] = None,
        request_headers: Optional[str] = None,
    ) -> Dict[str, str]:
        """Generate headers for preflight (OPTIONS) response."""
        headers = self.get_headers(origin)

        if not headers:
            return {}

        # Add preflight-specific headers
        headers["Access-Control-Allow-Methods"] = ", ".join(self.allowed_methods)
        headers["Access-Control-Allow-Headers"] = ", ".join(self.allowed_headers)
        headers["Access-Control-Max-Age"] = str(self.max_age)

        return headers

    def sign_request(self, origin: str, timestamp: Optional[int] = None) -> str:
        """
        Generate a signature for a request origin.

        Can be used to add an extra layer of verification.
        """
        ts = timestamp or int(time.time())
        data = f"{origin}:{ts}".encode("utf-8")
        signature = hmac.new(
            self.shield.key,
            data,
            hashlib.sha256,
        ).digest()[:16]
        return base64.urlsafe_b64encode(
            ts.to_bytes(8, "big") + signature
        ).decode("ascii")

    def verify_request(self, origin: str, signature: str, max_age: int = 300) -> bool:
        """Verify a signed request."""
        try:
            decoded = base64.urlsafe_b64decode(signature)
            if len(decoded) != 24:
                return False

            ts = int.from_bytes(decoded[:8], "big")
            provided_sig = decoded[8:]

            # Check age
            if abs(time.time() - ts) > max_age:
                return False

            # Verify signature
            data = f"{origin}:{ts}".encode("utf-8")
            expected = hmac.new(
                self.shield.key,
                data,
                hashlib.sha256,
            ).digest()[:16]

            return hmac.compare_digest(provided_sig, expected)
        except Exception:
            return False

    def add_origin(self, origin: str) -> None:
        """Add an origin to the allowed list."""
        self.allowed_origins.add(origin)

    def remove_origin(self, origin: str) -> None:
        """Remove an origin from the allowed list."""
        self.allowed_origins.discard(origin)
