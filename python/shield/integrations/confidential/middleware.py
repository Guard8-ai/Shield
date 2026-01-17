"""
FastAPI Attestation Middleware and Decorators

Provides middleware and decorators for protecting FastAPI endpoints
with TEE attestation verification.

Usage:
    from fastapi import FastAPI
    from shield.integrations.confidential import (
        AttestationMiddleware,
        requires_attestation,
        NitroAttestationProvider,
    )

    app = FastAPI()
    provider = NitroAttestationProvider()

    # Add middleware for all endpoints
    app.add_middleware(
        AttestationMiddleware,
        provider=provider,
        require_client_attestation=True,
    )

    # Or protect specific endpoints
    @app.get("/secure")
    @requires_attestation(provider=provider)
    async def secure_endpoint(attestation: AttestationResult):
        return {"verified": True}
"""

from __future__ import annotations

import base64
import functools
import json
import time
from typing import Any, Callable, Dict, List, Optional, Union

from shield.integrations.confidential.base import (
    AttestationError,
    AttestationProvider,
    AttestationResult,
    TEEType,
    TEEKeyManager,
)

try:
    from fastapi import Depends, FastAPI, HTTPException, Request, Response
    from fastapi.responses import JSONResponse
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.types import ASGIApp
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    Request = Any
    Response = Any
    HTTPException = Exception
    BaseHTTPMiddleware = object
    ASGIApp = Any


ATTESTATION_HEADER = "X-Attestation-Token"
ATTESTATION_TYPE_HEADER = "X-Attestation-Type"


class AttestationMiddleware(BaseHTTPMiddleware if FASTAPI_AVAILABLE else object):
    """
    FastAPI middleware for TEE attestation verification.

    Verifies attestation tokens in request headers before processing.
    Can also provide server attestation in responses.

    Args:
        app: The FastAPI application
        provider: Attestation provider for verification
        require_client_attestation: Whether to require client attestation
        provide_server_attestation: Whether to include server attestation in responses
        exclude_routes: Routes to exclude from attestation requirement
        attestation_header: Header name for attestation token
    """

    def __init__(
        self,
        app: ASGIApp,
        provider: AttestationProvider,
        require_client_attestation: bool = True,
        provide_server_attestation: bool = False,
        exclude_routes: Optional[List[str]] = None,
        attestation_header: str = ATTESTATION_HEADER,
    ):
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI required. Install with: pip install fastapi")

        super().__init__(app)
        self.provider = provider
        self.require_client_attestation = require_client_attestation
        self.provide_server_attestation = provide_server_attestation
        self.exclude_routes = exclude_routes or ["/docs", "/redoc", "/openapi.json", "/health"]
        self.attestation_header = attestation_header
        self._server_attestation_cache: Optional[bytes] = None
        self._cache_time: float = 0
        self._cache_ttl: float = 60

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with attestation verification."""
        path = request.url.path

        if any(path.startswith(prefix) for prefix in self.exclude_routes):
            return await call_next(request)

        if self.require_client_attestation:
            attestation_token = request.headers.get(self.attestation_header)

            if not attestation_token:
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "attestation_required",
                        "message": f"Missing {self.attestation_header} header",
                    },
                    headers={"WWW-Authenticate": f"Attestation realm=TEE"},
                )

            try:
                token_bytes = base64.b64decode(attestation_token)
            except Exception:
                token_bytes = attestation_token.encode()

            try:
                result = await self.provider.verify(token_bytes)
            except Exception as e:
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "attestation_failed",
                        "message": str(e),
                    },
                )

            if not result.verified:
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "attestation_invalid",
                        "message": result.error or "Attestation verification failed",
                    },
                )

            request.state.attestation = result

        response = await call_next(request)

        if self.provide_server_attestation:
            try:
                server_attestation = await self._get_server_attestation()
                response.headers["X-Server-Attestation"] = base64.b64encode(
                    server_attestation
                ).decode()
                response.headers["X-Server-TEE-Type"] = self.provider.tee_type.value
            except Exception:
                pass

        return response

    async def _get_server_attestation(self) -> bytes:
        """Get cached or fresh server attestation."""
        if (
            self._server_attestation_cache
            and time.time() - self._cache_time < self._cache_ttl
        ):
            return self._server_attestation_cache

        self._server_attestation_cache = await self.provider.generate_evidence()
        self._cache_time = time.time()
        return self._server_attestation_cache


def requires_attestation(
    provider: AttestationProvider,
    required_tee_types: Optional[List[TEEType]] = None,
    required_measurements: Optional[Dict[str, str]] = None,
    header_name: str = ATTESTATION_HEADER,
):
    """
    Decorator to protect FastAPI endpoints with attestation verification.

    Args:
        provider: Attestation provider for verification
        required_tee_types: Optional list of allowed TEE types
        required_measurements: Optional required measurements
        header_name: Header name for attestation token

    Usage:
        @app.get("/secure")
        @requires_attestation(
            provider=NitroAttestationProvider(),
            required_tee_types=[TEEType.NITRO],
        )
        async def secure_endpoint(request: Request):
            attestation = request.state.attestation
            return {"verified": True}
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if not request and "request" in kwargs:
                request = kwargs["request"]

            if not request:
                raise HTTPException(
                    status_code=500,
                    detail="Request object not found",
                )

            attestation_token = request.headers.get(header_name)

            if not attestation_token:
                raise HTTPException(
                    status_code=401,
                    detail=f"Missing {header_name} header",
                    headers={"WWW-Authenticate": "Attestation realm=TEE"},
                )

            try:
                token_bytes = base64.b64decode(attestation_token)
            except Exception:
                token_bytes = attestation_token.encode()

            try:
                result = await provider.verify(token_bytes)
            except AttestationError as e:
                raise HTTPException(
                    status_code=401,
                    detail=f"Attestation error: {e.message}",
                )

            if not result.verified:
                raise HTTPException(
                    status_code=401,
                    detail=result.error or "Attestation verification failed",
                )

            if required_tee_types and result.tee_type not in required_tee_types:
                raise HTTPException(
                    status_code=403,
                    detail=f"TEE type {result.tee_type.value} not allowed",
                )

            if required_measurements:
                for name, expected in required_measurements.items():
                    actual = result.measurements.get(name, "").lower()
                    if actual != expected.lower():
                        raise HTTPException(
                            status_code=403,
                            detail=f"Measurement {name} mismatch",
                        )

            request.state.attestation = result

            return await func(*args, **kwargs)

        return wrapper
    return decorator


def get_attestation_dependency(
    provider: AttestationProvider,
    header_name: str = ATTESTATION_HEADER,
):
    """
    Create a FastAPI dependency for attestation verification.

    Usage:
        provider = NitroAttestationProvider()
        AttestationDep = get_attestation_dependency(provider)

        @app.get("/secure")
        async def secure_endpoint(attestation: AttestationResult = Depends(AttestationDep)):
            return {"tee_type": attestation.tee_type.value}
    """
    async def dependency(request: Request) -> AttestationResult:
        attestation_token = request.headers.get(header_name)

        if not attestation_token:
            raise HTTPException(
                status_code=401,
                detail=f"Missing {header_name} header",
            )

        try:
            token_bytes = base64.b64decode(attestation_token)
        except Exception:
            token_bytes = attestation_token.encode()

        result = await provider.verify(token_bytes)

        if not result.verified:
            raise HTTPException(
                status_code=401,
                detail=result.error or "Attestation verification failed",
            )

        return result

    return dependency


class AttestationRouter:
    """
    FastAPI router for attestation endpoints.

    Provides standard endpoints for attestation operations:
    - GET /attestation: Get server attestation
    - POST /attestation/verify: Verify client attestation
    - GET /attestation/health: Health check with TEE status

    Usage:
        from fastapi import FastAPI
        from shield.integrations.confidential import AttestationRouter

        app = FastAPI()
        attestation_router = AttestationRouter(
            provider=NitroAttestationProvider(),
        )
        app.include_router(attestation_router.router, prefix="/api")
    """

    def __init__(
        self,
        provider: AttestationProvider,
        enable_server_attestation: bool = True,
        enable_verification: bool = True,
    ):
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI required. Install with: pip install fastapi")

        from fastapi import APIRouter

        self.provider = provider
        self.router = APIRouter(tags=["attestation"])
        self._server_attestation_cache: Optional[bytes] = None
        self._cache_time: float = 0
        self._cache_ttl: float = 60

        if enable_server_attestation:
            self._add_attestation_endpoint()

        if enable_verification:
            self._add_verification_endpoint()

        self._add_health_endpoint()

    def _add_attestation_endpoint(self):
        @self.router.get("/attestation")
        async def get_attestation(user_data: Optional[str] = None):
            """Get server attestation evidence."""
            try:
                ud = base64.b64decode(user_data) if user_data else None
                evidence = await self.provider.generate_evidence(user_data=ud)

                return {
                    "attestation": base64.b64encode(evidence).decode(),
                    "tee_type": self.provider.tee_type.value,
                    "timestamp": time.time(),
                }
            except AttestationError as e:
                raise HTTPException(
                    status_code=503,
                    detail=f"Attestation not available: {e.message}",
                )

    def _add_verification_endpoint(self):
        @self.router.post("/attestation/verify")
        async def verify_attestation(request: Request):
            """Verify attestation evidence."""
            body = await request.json()
            attestation_b64 = body.get("attestation")

            if not attestation_b64:
                raise HTTPException(
                    status_code=400,
                    detail="Missing 'attestation' field",
                )

            try:
                evidence = base64.b64decode(attestation_b64)
            except Exception:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid base64 encoding",
                )

            result = await self.provider.verify(evidence)

            return {
                "verified": result.verified,
                "tee_type": result.tee_type.value,
                "measurements": result.measurements,
                "claims": result.claims,
                "error": result.error,
            }

    def _add_health_endpoint(self):
        @self.router.get("/attestation/health")
        async def attestation_health():
            """Health check with TEE status."""
            try:
                evidence = await self.provider.generate_evidence()
                result = await self.provider.verify(evidence)

                return {
                    "status": "healthy",
                    "tee_type": self.provider.tee_type.value,
                    "in_tee": result.verified,
                    "measurements": result.measurements,
                }
            except AttestationError:
                return {
                    "status": "degraded",
                    "tee_type": self.provider.tee_type.value,
                    "in_tee": False,
                    "message": "Not running in TEE",
                }


class MutualAttestationClient:
    """
    Client for mutual attestation between services.

    Both client and server prove they are running in TEEs.

    Usage:
        client = MutualAttestationClient(
            server_url="https://api.example.com",
            provider=NitroAttestationProvider(),
        )

        # Verify server and make authenticated request
        response = await client.request(
            method="GET",
            path="/secure/data",
        )
    """

    def __init__(
        self,
        server_url: str,
        provider: AttestationProvider,
        verify_server: bool = True,
        expected_server_tee: Optional[TEEType] = None,
    ):
        self.server_url = server_url.rstrip("/")
        self.provider = provider
        self.verify_server = verify_server
        self.expected_server_tee = expected_server_tee
        self._client_attestation_cache: Optional[bytes] = None
        self._cache_time: float = 0
        self._cache_ttl: float = 60

    async def _get_client_attestation(self) -> bytes:
        """Get cached or fresh client attestation."""
        if (
            self._client_attestation_cache
            and time.time() - self._cache_time < self._cache_ttl
        ):
            return self._client_attestation_cache

        self._client_attestation_cache = await self.provider.generate_evidence()
        self._cache_time = time.time()
        return self._client_attestation_cache

    async def request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Make an attested request to the server.

        Args:
            method: HTTP method
            path: Request path
            data: Request data (for POST/PUT)
            headers: Additional headers

        Returns:
            Response data

        Raises:
            AttestationError: If attestation fails
        """
        from urllib.request import Request, urlopen
        from urllib.error import URLError

        client_attestation = await self._get_client_attestation()

        request_headers = headers or {}
        request_headers[ATTESTATION_HEADER] = base64.b64encode(
            client_attestation
        ).decode()
        request_headers[ATTESTATION_TYPE_HEADER] = self.provider.tee_type.value

        url = f"{self.server_url}{path}"

        body = None
        if data:
            body = json.dumps(data).encode()
            request_headers["Content-Type"] = "application/json"

        request = Request(url, data=body, headers=request_headers, method=method)

        try:
            with urlopen(request, timeout=30) as response:
                if self.verify_server:
                    server_attestation = response.headers.get("X-Server-Attestation")
                    if server_attestation:
                        server_evidence = base64.b64decode(server_attestation)
                        result = await self.provider.verify(server_evidence)

                        if not result.verified:
                            raise AttestationError(
                                f"Server attestation failed: {result.error}",
                                code="SERVER_ATTESTATION_FAILED",
                            )

                        if (
                            self.expected_server_tee
                            and result.tee_type != self.expected_server_tee
                        ):
                            raise AttestationError(
                                f"Server TEE type mismatch: expected "
                                f"{self.expected_server_tee.value}",
                                code="TEE_TYPE_MISMATCH",
                            )

                return json.loads(response.read())

        except URLError as e:
            raise AttestationError(
                f"Request failed: {e}",
                code="REQUEST_FAILED",
            )
