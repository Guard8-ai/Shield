"""
Shield Web Framework Integrations

Protect servers, browsers, and APIs with authenticated symmetric encryption.

Supported frameworks:
- FastAPI: ShieldMiddleware, shield_protected decorator
- Flask: ShieldFlask extension, shield_required decorator

Features:
- Request/response encryption
- Token-based authentication
- Rate limiting with encrypted counters
- CORS with encrypted cookies
- Browser-side encryption helpers
- Confidential Computing: TEE attestation evidence parsing + TEE-aware key
  management for AWS Nitro, GCP SEV, Azure MAA, Intel SGX. NOTE: the Python
  providers are fail-closed and do NOT cryptographically verify signatures —
  the verifying implementation is the Rust shield-core confidential module.
"""

from shield.integrations.fastapi import (
    ShieldMiddleware,
    shield_protected,
    ShieldAPIKeyAuth,
    ShieldTokenAuth,
)
from shield.integrations.flask import (
    ShieldFlask,
    shield_required,
    shield_encrypt_response,
)
from shield.integrations.protection import (
    APIProtector,
    RateLimiter,
    TokenBucket,
)
from shield.integrations.browser import (
    BrowserBridge,
    EncryptedCookie,
    SecureCORS,
)

# Confidential Computing (lazy import to avoid dependency issues)
def __getattr__(name):
    """Lazy import for confidential computing modules."""
    confidential_exports = {
        "AttestationProvider",
        "AttestationResult",
        "AttestationError",
        "TEEType",
        "TEEKeyManager",
        "NitroAttestationProvider",
        "SEVAttestationProvider",
        "MAAAttestationProvider",
        "SGXAttestationProvider",
        "AttestationMiddleware",
        "requires_attestation",
    }
    if name in confidential_exports:
        from shield.integrations import confidential
        return getattr(confidential, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    # FastAPI
    "ShieldMiddleware",
    "shield_protected",
    "ShieldAPIKeyAuth",
    "ShieldTokenAuth",
    # Flask
    "ShieldFlask",
    "shield_required",
    "shield_encrypt_response",
    # Protection
    "APIProtector",
    "RateLimiter",
    "TokenBucket",
    # Browser
    "BrowserBridge",
    "EncryptedCookie",
    "SecureCORS",
    # Confidential Computing
    "AttestationProvider",
    "AttestationResult",
    "AttestationError",
    "TEEType",
    "TEEKeyManager",
    "NitroAttestationProvider",
    "SEVAttestationProvider",
    "MAAAttestationProvider",
    "SGXAttestationProvider",
    "AttestationMiddleware",
    "requires_attestation",
]
