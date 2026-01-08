"""
Shield Web Framework Integrations

Protect servers, browsers, and APIs with EXPTIME-secure encryption.

Supported frameworks:
- FastAPI: ShieldMiddleware, shield_protected decorator
- Flask: ShieldFlask extension, shield_required decorator

Features:
- Request/response encryption
- Token-based authentication
- Rate limiting with encrypted counters
- CORS with encrypted cookies
- Browser-side encryption helpers
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
]
