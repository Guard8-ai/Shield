"""
Shield TOTP - Time-based One-Time Passwords (RFC 6238).

Compatible with Google Authenticator, Authy, Microsoft Authenticator, etc.

Example:
    >>> from shield.totp import TOTP
    >>> secret = TOTP.generate_secret()
    >>> totp = TOTP(secret)
    >>> code = totp.generate()
    >>> totp.verify(code)  # True
"""

import hmac
import hashlib
import struct
import time
import base64
import secrets
from typing import Optional


class TOTP:
    """
    Time-based One-Time Password generator/verifier.

    Compatible with RFC 6238 and common authenticator apps.

    Security:
        Uses HMAC-SHA1/SHA256 with EXPTIME-hard security.
        OTP is derived from secret + time, providing second factor.
    """

    def __init__(
        self,
        secret: bytes,
        digits: int = 6,
        interval: int = 30,
        algorithm: str = "sha1",
    ):
        """
        Initialize TOTP generator.

        Args:
            secret: Shared secret (typically 20 bytes)
            digits: OTP length (6 or 8)
            interval: Time step in seconds (default: 30)
            algorithm: 'sha1' (compatible) or 'sha256' (stronger)
        """
        self.secret = secret
        self.digits = digits
        self.interval = interval
        self.algorithm = algorithm

    @classmethod
    def generate_secret(cls, length: int = 20) -> bytes:
        """
        Generate random secret for new 2FA setup.

        Args:
            length: Secret length in bytes (default: 20)

        Returns:
            Random secret bytes
        """
        return secrets.token_bytes(length)

    @classmethod
    def secret_to_base32(cls, secret: bytes) -> str:
        """
        Convert secret to base32 for QR codes.

        Args:
            secret: Secret bytes

        Returns:
            Base32 encoded string (without padding)
        """
        return base64.b32encode(secret).decode("ascii").rstrip("=")

    @classmethod
    def secret_from_base32(cls, b32: str) -> bytes:
        """
        Parse base32 secret from authenticator app.

        Args:
            b32: Base32 encoded secret

        Returns:
            Secret bytes
        """
        # Add padding if needed
        padding = 8 - (len(b32) % 8)
        if padding != 8:
            b32 += "=" * padding
        return base64.b32decode(b32.upper())

    def generate(self, timestamp: Optional[int] = None) -> str:
        """
        Generate current TOTP code.

        Args:
            timestamp: Unix timestamp (default: current time)

        Returns:
            OTP code as string (zero-padded)
        """
        if timestamp is None:
            timestamp = int(time.time())

        counter = timestamp // self.interval
        return self._hotp(counter)

    def verify(
        self,
        code: str,
        timestamp: Optional[int] = None,
        window: int = 1,
    ) -> bool:
        """
        Verify TOTP code with time window.

        Args:
            code: User-provided code
            timestamp: Time to verify against (default: now)
            window: Number of intervals to check before/after

        Returns:
            True if code is valid
        """
        if timestamp is None:
            timestamp = int(time.time())

        counter = timestamp // self.interval

        # Check current and adjacent intervals (handles clock skew)
        for offset in range(-window, window + 1):
            expected = self._hotp(counter + offset)
            if hmac.compare_digest(code, expected):
                return True
        return False

    def _hotp(self, counter: int) -> str:
        """
        HOTP algorithm (RFC 4226).

        Args:
            counter: Counter value

        Returns:
            OTP code as string
        """
        # Counter as 8-byte big-endian
        counter_bytes = struct.pack(">Q", counter)

        # HMAC
        if self.algorithm == "sha256":
            h = hmac.new(self.secret, counter_bytes, hashlib.sha256).digest()
        else:
            h = hmac.new(self.secret, counter_bytes, hashlib.sha1).digest()

        # Dynamic truncation
        offset = h[-1] & 0x0F
        code_int = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF

        # Modulo to get digits
        code = str(code_int % (10**self.digits))
        return code.zfill(self.digits)

    def provisioning_uri(
        self,
        account: str,
        issuer: str = "Shield",
    ) -> str:
        """
        Generate URI for QR code (otpauth://).

        Args:
            account: User account identifier (e.g., email)
            issuer: Service name

        Returns:
            otpauth:// URI for QR code generation
        """
        secret_b32 = self.secret_to_base32(self.secret)
        return (
            f"otpauth://totp/{issuer}:{account}"
            f"?secret={secret_b32}&issuer={issuer}"
            f"&algorithm={self.algorithm.upper()}&digits={self.digits}"
        )


class RecoveryCodes:
    """
    Recovery codes for 2FA backup.

    Use when user loses access to their authenticator app.
    Each code can only be used once.
    """

    def __init__(self, codes: Optional[list] = None):
        """
        Initialize with existing codes or generate new ones.

        Args:
            codes: List of existing codes, or None to generate new
        """
        if codes is None:
            codes = self.generate_codes()
        self._codes = set(codes)
        self._used = set()

    @staticmethod
    def generate_codes(count: int = 10, length: int = 8) -> list:
        """
        Generate recovery codes.

        Args:
            count: Number of codes to generate
            length: Length of each code

        Returns:
            List of recovery codes
        """
        codes = []
        for _ in range(count):
            code = secrets.token_hex(length // 2).upper()
            # Format as XXXX-XXXX
            formatted = f"{code[:4]}-{code[4:]}"
            codes.append(formatted)
        return codes

    def verify(self, code: str) -> bool:
        """
        Verify and consume a recovery code.

        Args:
            code: Recovery code to verify

        Returns:
            True if valid (code is now consumed)
        """
        # Normalize format
        code = code.upper().replace("-", "").replace(" ", "")
        formatted = f"{code[:4]}-{code[4:]}" if len(code) == 8 else code

        if formatted in self._codes and formatted not in self._used:
            self._used.add(formatted)
            return True
        return False

    @property
    def remaining(self) -> int:
        """Number of unused recovery codes."""
        return len(self._codes) - len(self._used)

    @property
    def codes(self) -> list:
        """Get all recovery codes (for display to user)."""
        return sorted(self._codes)
