"""
FastAPI Integration for Shield Encryption

Provides middleware and decorators for protecting FastAPI applications
with EXPTIME-secure encryption.

Usage:
    from fastapi import FastAPI, Depends
    from shield.integrations import ShieldMiddleware, shield_protected, ShieldTokenAuth

    app = FastAPI()

    # Add encryption middleware (encrypts all responses)
    app.add_middleware(ShieldMiddleware, password="secret", service="api.example.com")

    # Or protect specific endpoints
    @app.get("/secure")
    @shield_protected(password="secret", service="api.example.com")
    async def secure_endpoint():
        return {"message": "This is encrypted"}

    # Token-based authentication
    auth = ShieldTokenAuth(password="secret", service="api.example.com")

    @app.get("/protected")
    async def protected(user: dict = Depends(auth)):
        return {"user": user}
"""

from __future__ import annotations

import base64
import functools
import json
import time
from typing import Any, Callable, Optional, Sequence

from shield import Shield

# Type hints for FastAPI (avoid hard dependency)
try:
    from fastapi import Request, Response, HTTPException
    from fastapi.security import APIKeyHeader, HTTPBearer
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.types import ASGIApp
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    # Stub types for when FastAPI isn't installed
    Request = Any
    Response = Any
    HTTPException = Exception
    BaseHTTPMiddleware = object
    ASGIApp = Any


class ShieldMiddleware(BaseHTTPMiddleware if FASTAPI_AVAILABLE else object):
    """
    FastAPI middleware that encrypts all JSON responses.

    The middleware:
    1. Intercepts outgoing JSON responses
    2. Encrypts the response body with Shield
    3. Returns encrypted payload with metadata

    Clients must decrypt responses using the same password/service.

    Args:
        app: The FastAPI application
        password: Encryption password
        service: Service identifier for key derivation
        encrypt_routes: Optional list of route prefixes to encrypt (default: all)
        exclude_routes: Optional list of route prefixes to exclude
    """

    def __init__(
        self,
        app: ASGIApp,
        password: str,
        service: str,
        encrypt_routes: Optional[Sequence[str]] = None,
        exclude_routes: Optional[Sequence[str]] = None,
    ):
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI is required. Install with: pip install fastapi")
        super().__init__(app)
        self.shield = Shield(password, service)
        self.service = service
        self.encrypt_routes = encrypt_routes
        self.exclude_routes = exclude_routes or ["/docs", "/redoc", "/openapi.json"]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and optionally encrypt response."""
        response = await call_next(request)

        # Check if we should encrypt this route
        path = request.url.path

        # Skip excluded routes
        if any(path.startswith(prefix) for prefix in self.exclude_routes):
            return response

        # If encrypt_routes specified, only encrypt matching routes
        if self.encrypt_routes:
            if not any(path.startswith(prefix) for prefix in self.encrypt_routes):
                return response

        # Only encrypt JSON responses
        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type:
            return response

        # Get response body
        body = b""
        async for chunk in response.body_iterator:
            body += chunk

        # Encrypt the body
        encrypted = self.shield.encrypt(body)
        encrypted_b64 = base64.b64encode(encrypted).decode("ascii")

        # Create new response with encrypted content
        new_body = json.dumps({
            "encrypted": True,
            "data": encrypted_b64,
            "service": self.service,
        }).encode("utf-8")

        return Response(
            content=new_body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type="application/json",
        )


def shield_protected(
    password: str,
    service: str,
    encrypt_request: bool = False,
    encrypt_response: bool = True,
):
    """
    Decorator to protect individual FastAPI endpoints with Shield encryption.

    Args:
        password: Encryption password
        service: Service identifier
        encrypt_request: Whether to decrypt incoming request body
        encrypt_response: Whether to encrypt outgoing response

    Usage:
        @app.post("/secure")
        @shield_protected(password="secret", service="api.example.com")
        async def secure_endpoint(data: dict):
            return {"result": "encrypted response"}
    """
    shield = Shield(password, service)

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Handle request decryption if enabled
            if encrypt_request and "request" in kwargs:
                request = kwargs["request"]
                body = await request.body()
                try:
                    payload = json.loads(body)
                    if payload.get("encrypted"):
                        encrypted = base64.b64decode(payload["data"])
                        decrypted = shield.decrypt(encrypted)
                        kwargs["body"] = json.loads(decrypted)
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    raise HTTPException(status_code=400, detail=f"Decryption failed: {e}")

            # Call the actual endpoint
            result = await func(*args, **kwargs)

            # Encrypt response if enabled
            if encrypt_response:
                if isinstance(result, dict):
                    body = json.dumps(result).encode("utf-8")
                    encrypted = shield.encrypt(body)
                    return {
                        "encrypted": True,
                        "data": base64.b64encode(encrypted).decode("ascii"),
                        "service": service,
                    }

            return result

        return wrapper
    return decorator


class ShieldAPIKeyAuth:
    """
    API Key authentication using Shield-encrypted keys.

    Generates and validates API keys that are HMAC-signed with Shield.

    Usage:
        auth = ShieldAPIKeyAuth(password="secret", service="api.example.com")

        # Generate a key for a user
        api_key = auth.generate_key(user_id="user123", permissions=["read", "write"])

        # Use as FastAPI dependency
        @app.get("/protected")
        async def protected(user: dict = Depends(auth)):
            return {"user_id": user["user_id"]}
    """

    def __init__(
        self,
        password: str,
        service: str,
        header_name: str = "X-API-Key",
        ttl: Optional[int] = None,
    ):
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI is required. Install with: pip install fastapi")
        self.shield = Shield(password, service)
        self.header_name = header_name
        self.ttl = ttl
        self._header = APIKeyHeader(name=header_name, auto_error=False)

    def generate_key(
        self,
        user_id: str,
        permissions: Optional[list[str]] = None,
        metadata: Optional[dict] = None,
    ) -> str:
        """Generate an API key for a user."""
        payload = {
            "user_id": user_id,
            "permissions": permissions or [],
            "metadata": metadata or {},
            "created_at": int(time.time()),
        }
        if self.ttl:
            payload["expires_at"] = int(time.time()) + self.ttl

        # Serialize and encrypt
        data = json.dumps(payload).encode("utf-8")
        encrypted = self.shield.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode("ascii")

    def validate_key(self, api_key: str) -> Optional[dict]:
        """Validate an API key and return the payload."""
        try:
            encrypted = base64.urlsafe_b64decode(api_key)
            decrypted = self.shield.decrypt(encrypted)
            payload = json.loads(decrypted)

            # Check expiration
            if "expires_at" in payload:
                if time.time() > payload["expires_at"]:
                    return None

            return payload
        except Exception:
            return None

    async def __call__(self, request: Request) -> dict:
        """FastAPI dependency for authentication."""
        api_key = request.headers.get(self.header_name)
        if not api_key:
            raise HTTPException(
                status_code=401,
                detail="Missing API key",
                headers={"WWW-Authenticate": f"ApiKey realm={self.header_name}"},
            )

        payload = self.validate_key(api_key)
        if not payload:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired API key",
            )

        return payload


class ShieldTokenAuth:
    """
    Bearer token authentication using Shield encryption.

    Creates secure session tokens with encrypted payloads.

    Usage:
        auth = ShieldTokenAuth(password="secret", service="api.example.com")

        # Create a token after login
        token = auth.create_token(user_id="user123", roles=["admin"])

        # Validate in protected endpoints
        @app.get("/protected")
        async def protected(user: dict = Depends(auth)):
            return {"user_id": user["user_id"]}
    """

    def __init__(
        self,
        password: str,
        service: str,
        ttl: int = 3600,
    ):
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI is required. Install with: pip install fastapi")
        self.shield = Shield(password, service)
        self.ttl = ttl
        self._bearer = HTTPBearer(auto_error=False)

    def create_token(
        self,
        user_id: str,
        roles: Optional[list[str]] = None,
        claims: Optional[dict] = None,
    ) -> str:
        """Create a bearer token for a user."""
        payload = {
            "sub": user_id,
            "roles": roles or [],
            "claims": claims or {},
            "iat": int(time.time()),
            "exp": int(time.time()) + self.ttl,
        }

        data = json.dumps(payload).encode("utf-8")
        encrypted = self.shield.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode("ascii")

    def validate_token(self, token: str) -> Optional[dict]:
        """Validate a token and return the payload."""
        try:
            encrypted = base64.urlsafe_b64decode(token)
            decrypted = self.shield.decrypt(encrypted)
            payload = json.loads(decrypted)

            # Check expiration
            if time.time() > payload.get("exp", 0):
                return None

            return payload
        except Exception:
            return None

    async def __call__(self, request: Request) -> dict:
        """FastAPI dependency for authentication."""
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header[7:]  # Remove "Bearer " prefix
        payload = self.validate_token(token)
        if not payload:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token",
            )

        return payload
