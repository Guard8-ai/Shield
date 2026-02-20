"""
FIDO2/WebAuthn FastAPI integration for passwordless authentication.

This module provides FastAPI endpoints for FIDO2 registration and authentication
using Shield-encrypted credential storage.

Example:
    from fastapi import FastAPI
    from shield.integrations.fido2_api import Fido2Router

    app = FastAPI()
    app.include_router(Fido2Router(password="master_password", service="myapp.com"))

Note:
    This is a simplified implementation demonstrating the API structure.
    Production use should integrate with the Rust fido2 module via FFI/PyO3.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Type alias for challenge storage
ChallengeStorage = Dict[str, Dict[str, Any]]


class RegistrationBeginRequest(BaseModel):
    """Request to begin FIDO2 registration"""

    username: str = Field(..., min_length=1, max_length=255)
    display_name: str = Field(..., min_length=1, max_length=255)


class RegistrationCompleteRequest(BaseModel):
    """Request to complete FIDO2 registration"""

    credential: Dict[str, Any]
    session_id: str


class LoginBeginRequest(BaseModel):
    """Request to begin FIDO2 authentication"""

    username: str = Field(..., min_length=1, max_length=255)


class LoginCompleteRequest(BaseModel):
    """Request to complete FIDO2 authentication"""

    credential: Dict[str, Any]
    session_id: str


class Fido2Router:
    """FastAPI router for FIDO2/WebAuthn endpoints"""

    def __init__(
        self,
        password: str,
        service: str,
        rp_id: str = "localhost",
        rp_name: str = "Shield App",
        origin: str = "http://localhost:8000",
        timeout_ms: int = 60000,
    ):
        """
        Initialize FIDO2 router.

        Args:
            password: Master password for Shield encryption
            service: Service identifier for Shield
            rp_id: Relying party ID (domain)
            rp_name: Relying party name
            origin: Expected origin for WebAuthn
            timeout_ms: Challenge timeout in milliseconds
        """
        self.password = password
        self.service = service
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin
        self.timeout_ms = timeout_ms

        # In-memory storage (production should use Redis)
        self.challenges: ChallengeStorage = {}
        self.credentials: Dict[str, List[Dict[str, Any]]] = {}

        # Create router
        self.router = APIRouter(prefix="/fido2", tags=["fido2"])
        self._setup_routes()

    def _setup_routes(self) -> None:
        """Set up API routes"""

        @self.router.post("/register/begin")
        async def register_begin(
            request: RegistrationBeginRequest,
        ) -> Dict[str, Any]:
            """Begin FIDO2 registration"""
            # Generate session and challenge
            session_id = secrets.token_urlsafe(32)
            user_id = hashlib.sha256(request.username.encode()).digest()
            user_id_b64 = base64.urlsafe_b64encode(user_id).decode().rstrip("=")

            challenge = secrets.token_bytes(32)
            challenge_b64 = base64.urlsafe_b64encode(challenge).decode().rstrip("=")

            # Store challenge
            self.challenges[session_id] = {
                "challenge": challenge,
                "username": request.username,
                "user_id": user_id,
                "expires_at": time.time() + (self.timeout_ms / 1000),
                "type": "registration",
            }

            return {
                "session_id": session_id,
                "challenge": challenge_b64,
                "rp": {"id": self.rp_id, "name": self.rp_name},
                "user": {
                    "id": user_id_b64,
                    "name": request.username,
                    "displayName": request.display_name,
                },
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": -7},  # ES256
                    {"type": "public-key", "alg": -257},  # RS256
                ],
                "timeout": self.timeout_ms,
                "attestation": "none",
            }

        @self.router.post("/register/complete")
        async def register_complete(
            request: RegistrationCompleteRequest,
        ) -> Dict[str, str]:
            """Complete FIDO2 registration"""
            # Validate session
            session = self.challenges.get(request.session_id)
            if not session or session["type"] != "registration":
                raise HTTPException(status_code=400, detail="Invalid session")

            if time.time() > session["expires_at"]:
                del self.challenges[request.session_id]
                raise HTTPException(status_code=400, detail="Challenge expired")

            # Extract credential data (simplified verification)
            credential = request.credential
            credential_id = credential.get("rawId", "")
            # In production, verify attestation object and signature

            # Store credential (Shield-encrypted in production)
            username = session["username"]
            if username not in self.credentials:
                self.credentials[username] = []

            self.credentials[username].append(
                {
                    "credential_id": credential_id,
                    "public_key": credential.get("response", {}).get(
                        "attestationObject", ""
                    ),
                    "counter": 0,
                    "created_at": time.time(),
                }
            )

            # Clean up session
            del self.challenges[request.session_id]

            return {"status": "success", "message": "Registration complete"}

        @self.router.post("/login/begin")
        async def login_begin(request: LoginBeginRequest) -> Dict[str, Any]:
            """Begin FIDO2 authentication"""
            # Check if user has credentials
            if request.username not in self.credentials:
                raise HTTPException(status_code=404, detail="User not found")

            user_credentials = self.credentials[request.username]
            if not user_credentials:
                raise HTTPException(status_code=404, detail="No credentials found")

            # Generate challenge
            session_id = secrets.token_urlsafe(32)
            challenge = secrets.token_bytes(32)
            challenge_b64 = base64.urlsafe_b64encode(challenge).decode().rstrip("=")

            # Store challenge
            self.challenges[session_id] = {
                "challenge": challenge,
                "username": request.username,
                "expires_at": time.time() + (self.timeout_ms / 1000),
                "type": "authentication",
            }

            # Build allowed credentials
            allowed_credentials = [
                {
                    "type": "public-key",
                    "id": cred["credential_id"],
                }
                for cred in user_credentials
            ]

            return {
                "session_id": session_id,
                "challenge": challenge_b64,
                "allowCredentials": allowed_credentials,
                "timeout": self.timeout_ms,
                "rpId": self.rp_id,
            }

        @self.router.post("/login/complete")
        async def login_complete(
            request: LoginCompleteRequest,
        ) -> Dict[str, str]:
            """Complete FIDO2 authentication"""
            # Validate session
            session = self.challenges.get(request.session_id)
            if not session or session["type"] != "authentication":
                raise HTTPException(status_code=400, detail="Invalid session")

            if time.time() > session["expires_at"]:
                del self.challenges[request.session_id]
                raise HTTPException(status_code=400, detail="Challenge expired")

            # Verify signature (simplified)
            username = session["username"]
            credential_id = request.credential.get("rawId", "")

            # Find credential
            user_creds = self.credentials.get(username, [])
            credential = next(
                (c for c in user_creds if c["credential_id"] == credential_id), None
            )

            if not credential:
                raise HTTPException(status_code=400, detail="Credential not found")

            # In production: verify signature with public key
            # For now, just generate a token

            # Generate access token (use Shield IdentityProvider in production)
            token_payload = {
                "sub": username,
                "iat": time.time(),
                "exp": time.time() + 3600,
            }
            token = base64.urlsafe_b64encode(json.dumps(token_payload).encode()).decode()

            # Update counter
            credential["counter"] += 1

            # Clean up session
            del self.challenges[request.session_id]

            return {"access_token": token, "token_type": "Bearer"}

        @self.router.get("/credentials")
        async def list_credentials(username: str) -> Dict[str, Any]:
            """List user credentials"""
            credentials = self.credentials.get(username, [])
            return {
                "username": username,
                "credentials": [
                    {
                        "credential_id": c["credential_id"][:16] + "...",
                        "created_at": c["created_at"],
                        "counter": c["counter"],
                    }
                    for c in credentials
                ],
            }

        @self.router.delete("/credentials/{credential_id}")
        async def delete_credential(
            username: str, credential_id: str
        ) -> Dict[str, str]:
            """Delete a credential"""
            if username not in self.credentials:
                raise HTTPException(status_code=404, detail="User not found")

            user_creds = self.credentials[username]
            initial_len = len(user_creds)
            self.credentials[username] = [
                c for c in user_creds if c["credential_id"] != credential_id
            ]

            if len(self.credentials[username]) == initial_len:
                raise HTTPException(status_code=404, detail="Credential not found")

            return {"status": "success", "message": "Credential deleted"}


def create_fido2_app(
    password: str,
    service: str,
    cors_origins: Optional[List[str]] = None,
) -> APIRouter:
    """
    Create a FIDO2 FastAPI router with CORS.

    Args:
        password: Master password for Shield encryption
        service: Service identifier
        cors_origins: Allowed CORS origins (default: ["http://localhost:3000"])

    Returns:
        Configured FastAPI router
    """
    if cors_origins is None:
        cors_origins = ["http://localhost:3000"]

    fido2_router = Fido2Router(password=password, service=service)

    return fido2_router.router
