"""
Shield - Authenticated Symmetric Encryption Library

Symmetric authenticated encryption with 256-bit keys (~128-bit post-quantum security).
Brute-forcing a full 256-bit key requires 2^256 operations; this relies on the standard assumption that SHA-256/HMAC have no exploitable structure (an assumption, not a mathematical proof).

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
    256-bit keys give 256-bit classical and ~128-bit post-quantum brute-force resistance.
"""

__version__ = "2.2.0"
__author__ = "Eliran Sabag"
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
from shield.channel import ShieldChannel, ChannelConfig, ShieldListener
from shield.fingerprint import FingerprintMode, FingerprintError

# Post-quantum hybrid key exchange (optional: requires the `pq` extra / cryptography).
# Imported lazily so the dependency-free core still works without it installed.
try:
    from shield.pqhybrid import HybridPrivateKey, HybridPublicKey, initiate as pq_initiate
    _HAS_PQ = True
except ImportError:  # pragma: no cover - exercised only when cryptography is absent
    _HAS_PQ = False

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
    # Secure Channel
    "ShieldChannel",
    "ChannelConfig",
    "ShieldListener",
    # Hardware Fingerprinting (v2.1)
    "FingerprintMode",
    "FingerprintError",
]

# Post-quantum hybrid key exchange names (only when the optional extra is installed).
if _HAS_PQ:
    __all__ += ["HybridPrivateKey", "HybridPublicKey", "pq_initiate"]
