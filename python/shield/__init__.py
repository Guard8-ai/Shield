"""
Shield - EXPTIME-Secure Encryption Library

Symmetric cryptography with proven exponential-time security.
Breaking requires 2^256 operations - no shortcut exists.

Usage:
    from shield import Shield, quick_encrypt, quick_decrypt

    # Password-based encryption
    s = Shield("password", "service.com")
    encrypted = s.encrypt(b"secret data")
    decrypted = s.decrypt(encrypted)

    # Pre-shared key encryption
    key = os.urandom(32)
    encrypted = quick_encrypt(key, b"data")
    decrypted = quick_decrypt(key, encrypted)

Security:
    Shield uses PBKDF2-SHA256 + SHA256-CTR + HMAC-SHA256.
    All primitives have EXPTIME-hard security guarantees.
"""

__version__ = "0.1.0"
__author__ = "Guard8.ai"
__license__ = "CC0-1.0"

from shield.core import Shield, quick_encrypt, quick_decrypt
from shield.stream import StreamCipher
from shield.ratchet import RatchetSession
from shield.totp import TOTP, RecoveryCodes
from shield.signatures import SymmetricSignature, LamportSignature
from shield.exchange import PAKEExchange, QRExchange, KeySplitter
from shield.rotation import KeyRotationManager
from shield.group import GroupEncryption, BroadcastEncryption
from shield.identity import IdentityProvider, Identity, Session, SecureSession

__all__ = [
    # Core
    "Shield",
    "quick_encrypt",
    "quick_decrypt",
    # Streaming
    "StreamCipher",
    # Forward Secrecy
    "RatchetSession",
    # 2FA
    "TOTP",
    "RecoveryCodes",
    # Signatures
    "SymmetricSignature",
    "LamportSignature",
    # Key Exchange
    "PAKEExchange",
    "QRExchange",
    "KeySplitter",
    # Key Rotation
    "KeyRotationManager",
    # Group Encryption
    "GroupEncryption",
    "BroadcastEncryption",
    # Identity/SSO
    "IdentityProvider",
    "Identity",
    "Session",
    "SecureSession",
]
