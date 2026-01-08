"""
Flask Integration for Shield Encryption

Provides extension and decorators for protecting Flask applications
with EXPTIME-secure encryption.

Usage:
    from flask import Flask
    from shield.integrations import ShieldFlask, shield_required

    app = Flask(__name__)
    shield = ShieldFlask(app, password="secret", service="api.example.com")

    @app.route("/secure")
    @shield_required(password="secret", service="api.example.com")
    def secure_endpoint():
        return {"message": "This is encrypted"}

    # Or encrypt responses explicitly
    @app.route("/data")
    @shield_encrypt_response(password="secret", service="api.example.com")
    def data_endpoint():
        return {"data": "sensitive"}
"""

from __future__ import annotations

import base64
import functools
import json
import time
from typing import Any, Callable, Optional, Sequence

from shield import Shield

# Type hints for Flask (avoid hard dependency)
try:
    from flask import Flask, Request, Response, request, g, jsonify, abort
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    Flask = Any
    Request = Any
    Response = Any


class ShieldFlask:
    """
    Flask extension for Shield encryption.

    Provides automatic encryption/decryption of requests and responses,
    as well as authentication helpers.

    Args:
        app: Flask application (optional, can use init_app later)
        password: Encryption password
        service: Service identifier for key derivation
        encrypt_routes: Optional list of route prefixes to encrypt
        exclude_routes: Optional list of route prefixes to exclude

    Usage:
        app = Flask(__name__)
        shield = ShieldFlask(app, password="secret", service="api.example.com")

        # Or with factory pattern
        shield = ShieldFlask(password="secret", service="api.example.com")
        shield.init_app(app)
    """

    def __init__(
        self,
        app: Optional[Flask] = None,
        password: Optional[str] = None,
        service: Optional[str] = None,
        encrypt_routes: Optional[Sequence[str]] = None,
        exclude_routes: Optional[Sequence[str]] = None,
    ):
        if not FLASK_AVAILABLE:
            raise ImportError("Flask is required. Install with: pip install flask")

        self.password = password
        self.service = service
        self.shield = Shield(password, service) if password and service else None
        self.encrypt_routes = encrypt_routes
        self.exclude_routes = exclude_routes or ["/static", "/health", "/favicon.ico"]

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """Initialize the extension with a Flask app."""
        # Store extension on app
        app.extensions = getattr(app, "extensions", {})
        app.extensions["shield"] = self

        # Get config from app if not set
        if not self.password:
            self.password = app.config.get("SHIELD_PASSWORD")
        if not self.service:
            self.service = app.config.get("SHIELD_SERVICE")

        if self.password and self.service:
            self.shield = Shield(self.password, self.service)

        # Register before/after request handlers
        app.before_request(self._before_request)
        app.after_request(self._after_request)

    def _should_process(self, path: str) -> bool:
        """Check if path should be encrypted/decrypted."""
        # Skip excluded routes
        if any(path.startswith(prefix) for prefix in self.exclude_routes):
            return False

        # If encrypt_routes specified, only process matching routes
        if self.encrypt_routes:
            return any(path.startswith(prefix) for prefix in self.encrypt_routes)

        return True

    def _before_request(self) -> None:
        """Decrypt incoming request body if encrypted."""
        if not self.shield or not self._should_process(request.path):
            return

        if request.is_json and request.content_length:
            try:
                data = request.get_json(force=True)
                if isinstance(data, dict) and data.get("encrypted"):
                    encrypted = base64.b64decode(data["data"])
                    decrypted = self.shield.decrypt(encrypted)
                    g.shield_decrypted_body = json.loads(decrypted)
            except Exception:
                pass  # Let the route handle invalid data

    def _after_request(self, response: Response) -> Response:
        """Encrypt outgoing response if applicable."""
        if not self.shield or not self._should_process(request.path):
            return response

        # Only encrypt JSON responses
        if response.content_type and "application/json" in response.content_type:
            try:
                body = response.get_data()
                encrypted = self.shield.encrypt(body)
                encrypted_b64 = base64.b64encode(encrypted).decode("ascii")

                new_body = json.dumps({
                    "encrypted": True,
                    "data": encrypted_b64,
                    "service": self.service,
                })

                response.set_data(new_body)
            except Exception:
                pass  # Return original response on error

        return response

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using Shield."""
        if not self.shield:
            raise ValueError("Shield not initialized. Provide password and service.")
        return self.shield.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using Shield."""
        if not self.shield:
            raise ValueError("Shield not initialized. Provide password and service.")
        return self.shield.decrypt(data)

    def generate_token(
        self,
        user_id: str,
        roles: Optional[list[str]] = None,
        claims: Optional[dict] = None,
        ttl: int = 3600,
    ) -> str:
        """Generate an encrypted token for a user."""
        if not self.shield:
            raise ValueError("Shield not initialized. Provide password and service.")

        payload = {
            "sub": user_id,
            "roles": roles or [],
            "claims": claims or {},
            "iat": int(time.time()),
            "exp": int(time.time()) + ttl,
        }

        data = json.dumps(payload).encode("utf-8")
        encrypted = self.shield.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode("ascii")

    def validate_token(self, token: str) -> Optional[dict]:
        """Validate a token and return the payload."""
        if not self.shield:
            return None

        try:
            encrypted = base64.urlsafe_b64decode(token)
            decrypted = self.shield.decrypt(encrypted)
            payload = json.loads(decrypted)

            if time.time() > payload.get("exp", 0):
                return None

            return payload
        except Exception:
            return None


def shield_required(
    password: str,
    service: str,
    require_auth: bool = True,
):
    """
    Decorator to require Shield authentication on a Flask route.

    Args:
        password: Encryption password
        service: Service identifier
        require_auth: Whether to require a valid token (default: True)

    Usage:
        @app.route("/protected")
        @shield_required(password="secret", service="api.example.com")
        def protected():
            user = g.shield_user  # Access authenticated user
            return {"user_id": user["sub"]}
    """
    shield = Shield(password, service)

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Check Authorization header
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                if require_auth:
                    abort(401, description="Missing bearer token")
                g.shield_user = None
                return func(*args, **kwargs)

            token = auth_header[7:]  # Remove "Bearer " prefix

            try:
                encrypted = base64.urlsafe_b64decode(token)
                decrypted = shield.decrypt(encrypted)
                payload = json.loads(decrypted)

                # Check expiration
                if time.time() > payload.get("exp", 0):
                    if require_auth:
                        abort(401, description="Token expired")
                    g.shield_user = None
                    return func(*args, **kwargs)

                g.shield_user = payload
            except Exception:
                if require_auth:
                    abort(401, description="Invalid token")
                g.shield_user = None

            return func(*args, **kwargs)

        return wrapper
    return decorator


def shield_encrypt_response(password: str, service: str):
    """
    Decorator to encrypt the response of a Flask route.

    Args:
        password: Encryption password
        service: Service identifier

    Usage:
        @app.route("/data")
        @shield_encrypt_response(password="secret", service="api.example.com")
        def data_endpoint():
            return {"sensitive": "data"}
    """
    shield = Shield(password, service)

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            # Handle dict/list responses
            if isinstance(result, (dict, list)):
                body = json.dumps(result).encode("utf-8")
                encrypted = shield.encrypt(body)
                return jsonify({
                    "encrypted": True,
                    "data": base64.b64encode(encrypted).decode("ascii"),
                    "service": service,
                })

            # Handle tuple responses (data, status_code)
            if isinstance(result, tuple) and len(result) >= 1:
                data = result[0]
                status = result[1] if len(result) > 1 else 200
                headers = result[2] if len(result) > 2 else None

                if isinstance(data, (dict, list)):
                    body = json.dumps(data).encode("utf-8")
                    encrypted = shield.encrypt(body)
                    response = jsonify({
                        "encrypted": True,
                        "data": base64.b64encode(encrypted).decode("ascii"),
                        "service": service,
                    })
                    response.status_code = status
                    if headers:
                        response.headers.update(headers)
                    return response

            return result

        return wrapper
    return decorator


class FlaskAPIKeyAuth:
    """
    API Key authentication for Flask using Shield encryption.

    Usage:
        auth = FlaskAPIKeyAuth(password="secret", service="api.example.com")

        # Generate a key
        api_key = auth.generate_key(user_id="user123", permissions=["read"])

        # Protect routes
        @app.route("/api/data")
        @auth.required
        def api_data():
            return {"user": g.api_user}
    """

    def __init__(
        self,
        password: str,
        service: str,
        header_name: str = "X-API-Key",
        ttl: Optional[int] = None,
    ):
        if not FLASK_AVAILABLE:
            raise ImportError("Flask is required. Install with: pip install flask")
        self.shield = Shield(password, service)
        self.header_name = header_name
        self.ttl = ttl

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

        data = json.dumps(payload).encode("utf-8")
        encrypted = self.shield.encrypt(data)
        return base64.urlsafe_b64encode(encrypted).decode("ascii")

    def validate_key(self, api_key: str) -> Optional[dict]:
        """Validate an API key and return the payload."""
        try:
            encrypted = base64.urlsafe_b64decode(api_key)
            decrypted = self.shield.decrypt(encrypted)
            payload = json.loads(decrypted)

            if "expires_at" in payload:
                if time.time() > payload["expires_at"]:
                    return None

            return payload
        except Exception:
            return None

    def required(self, func: Callable) -> Callable:
        """Decorator to require API key authentication."""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            api_key = request.headers.get(self.header_name)
            if not api_key:
                abort(401, description=f"Missing {self.header_name} header")

            payload = self.validate_key(api_key)
            if not payload:
                abort(401, description="Invalid or expired API key")

            g.api_user = payload
            return func(*args, **kwargs)

        return wrapper
