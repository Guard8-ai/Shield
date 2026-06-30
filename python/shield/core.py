"""
Shield Core - Password-based symmetric encryption (wire format v4).

v4 replaces the previous custom SHA-256 keystream + HMAC construction with a
**standard AEAD** (AES-256-GCM by default, ChaCha20-Poly1305 optional) from the
audited ``cryptography`` library. No cryptography is hand-rolled: key derivation
uses PBKDF2-HMAC-SHA256 + HKDF-SHA256-Expand, and encryption uses the library's
AEAD primitives. The wire format matches every other Shield binding byte-for-byte
(see ``tests/v4_test_vectors.json``).

Security:
    - PBKDF2-HMAC-SHA256, 600,000 iterations, random per-instance 16-byte salt
    - AEAD key = HKDF-SHA256-Expand(master, "shield/aead/v4", 32)
    - AES-256-GCM (suite 0x01) or ChaCha20-Poly1305 (suite 0x02)
    - 12-byte random nonce per message; 128-bit AEAD tag
    - 32-128 random padding bytes inside the AEAD plaintext (length hiding)
"""

import os
import secrets
import struct
import time
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Key derivation iterations (OWASP 2023 floor for PBKDF2-HMAC-SHA256)
PBKDF2_ITERATIONS = 600_000

# Sizes in bytes
NONCE_SIZE = 12  # 96-bit AEAD nonce
TAG_SIZE = 16    # 128-bit AEAD tag
SALT_SIZE = 16

# Version bytes (authenticated, leading byte of the ciphertext)
VERSION_PASSWORD = 0x03  # password mode: 0x03 || suite || salt(16) || nonce(12) || ct||tag
VERSION_KEY = 0x13       # pre-shared-key mode: 0x13 || suite || nonce(12) || ct||tag

# Cipher-suite identifiers
SUITE_AES_256_GCM = 0x01
SUITE_CHACHA20_POLY1305 = 0x02

# Inner-plaintext layout: timestamp_ms(8) || pad_len(1) || padding || message
INNER_HEADER_SIZE = 9
MIN_PADDING = 32
MAX_PADDING = 128

# HKDF-Expand info string deriving the AEAD key from the master key
HKDF_AEAD_INFO = b"shield/aead/v4"


def _derive_aead_key(master_key: bytes) -> bytes:
    """AEAD key = HKDF-SHA256-Expand(master_key, info="shield/aead/v4", L=32)."""
    return HKDFExpand(algorithm=hashes.SHA256(), length=32, info=HKDF_AEAD_INFO).derive(
        master_key
    )


def _aead_for_suite(suite: int, key: bytes):
    """Return an AEAD object for the given suite, or None if the suite is unknown."""
    if suite == SUITE_AES_256_GCM:
        return AESGCM(key)
    if suite == SUITE_CHACHA20_POLY1305:
        return ChaCha20Poly1305(key)
    return None


class Shield:
    """
    Authenticated symmetric encryption using a standard AEAD.

    Keys are derived from a password (PBKDF2 + HKDF) or supplied as a 32-byte
    pre-shared key. Data is sealed with AES-256-GCM (default) or
    ChaCha20-Poly1305. Each message carries 32-128 random padding bytes inside the
    AEAD plaintext so ciphertext length does not reveal the exact message length.

    The freshness window (timestamp-based) rejects stale messages but is NOT full
    replay protection — use RatchetSession for per-message counters.

    Example:
        >>> s = Shield("my_password", "github.com")
        >>> encrypted = s.encrypt(b"secret data")
        >>> decrypted = s.decrypt(encrypted)
        >>> assert decrypted == b"secret data"
    """

    def __init__(
        self,
        password: str,
        service: str,
        salt: Optional[bytes] = None,
        iterations: int = PBKDF2_ITERATIONS,
        max_age_ms: Optional[int] = 60_000,
        suite: int = SUITE_AES_256_GCM,
    ):
        """
        Initialize Shield with password and service name.

        Args:
            password: User's password for this service
            service: Service identifier (e.g., "github.com")
            salt: Optional explicit 16-byte salt. If omitted, a cryptographically
                  secure random 16-byte salt is generated per instance.
            iterations: PBKDF2 iterations (default: 600,000)
            max_age_ms: Maximum message age in ms for the freshness window
                       (default 60000; None = disabled)
            suite: Cipher suite for encryption (default AES-256-GCM)

        Security:
            master = PBKDF2-HMAC-SHA256(password, random_salt || service,
            iterations, dklen=32); aead_key = HKDF-Expand(master,
            "shield/aead/v4", 32). The random salt is stored in the ciphertext
            header so a recipient with the same password+service can re-derive the
            key. ``service`` is retained as a domain separator.
        """
        if salt is None:
            salt = secrets.token_bytes(SALT_SIZE)

        self._password = password.encode()
        self._service = service.encode()
        self._iterations = iterations
        self._salt = salt
        self._suite = suite
        # Cache of derived master keys keyed by the 16-byte salt, so decrypting
        # many messages from the same sender only runs PBKDF2 once per salt.
        self._key_cache: dict = {}

        self._key = self._derive_key(salt)
        self._aead_key = _derive_aead_key(self._key)
        self._max_age_ms = max_age_ms

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive the 32-byte master key for a given salt (cached)."""
        cached = self._key_cache.get(salt)
        if cached is not None:
            return cached
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt + self._service,
            iterations=self._iterations,
        )
        key = kdf.derive(self._password)
        self._key_cache[salt] = key
        return key

    @classmethod
    def with_key(
        cls,
        key: bytes,
        max_age_ms: Optional[int] = 60_000,
        suite: int = SUITE_AES_256_GCM,
    ) -> "Shield":
        """
        Create Shield instance with a pre-shared key (no password derivation).

        Args:
            key: 32-byte symmetric key
            max_age_ms: Freshness window in ms (default 60s); None to disable
            suite: Cipher suite for encryption (default AES-256-GCM)

        Raises:
            ValueError: If key is not 32 bytes
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")

        instance = cls.__new__(cls)
        instance._key = key
        instance._aead_key = _derive_aead_key(key)
        instance._max_age_ms = max_age_ms
        instance._suite = suite
        # Pre-shared-key mode: no password, no salt.
        instance._password = None
        instance._service = None
        instance._iterations = None
        instance._salt = None
        instance._key_cache = {}
        return instance

    @classmethod
    def with_fingerprint(cls, password: str, service: str, mode: str = "combined") -> "Shield":
        """
        Create Shield with hardware fingerprinting (device-bound encryption).

        Derives keys from password + hardware identifier, binding encryption to
        the physical device.

        Args:
            password: User's password
            service: Service identifier (e.g., "github.com")
            mode: Fingerprint mode - "none", "motherboard", "cpu", or "combined"

        Raises:
            FingerprintError: If hardware identifiers cannot be collected

        Security:
            - Binding Strength: MEDIUM (hardware IDs are stable but replaceable)
            - Spoofability: LOW-MEDIUM (requires hardware access or VM manipulation)
            - Portability: NONE (keys are device-bound by design)
        """
        from .fingerprint import collect_fingerprint, FingerprintMode

        mode_map = {
            "none": FingerprintMode.NONE,
            "motherboard": FingerprintMode.MOTHERBOARD,
            "cpu": FingerprintMode.CPU,
            "combined": FingerprintMode.COMBINED,
        }
        fingerprint_mode = mode_map.get(mode.lower())
        if fingerprint_mode is None:
            raise ValueError(f"Invalid fingerprint mode: {mode}")

        fingerprint = collect_fingerprint(fingerprint_mode)
        combined_password = f"{password}:{fingerprint}" if fingerprint else password
        return cls(combined_password, service)

    @staticmethod
    def _build_aad(suite: int, salt: Optional[bytes]) -> bytes:
        """AEAD additional data (= wire prefix before the nonce)."""
        if salt is not None:
            return bytes([VERSION_PASSWORD, suite]) + salt
        return bytes([VERSION_KEY, suite])

    @staticmethod
    def _sample_pad_len() -> int:
        """Random padding length in [32, 128] via rejection sampling (no modulo bias)."""
        pad_range = MAX_PADDING - MIN_PADDING + 1  # 97
        while True:
            val = os.urandom(1)[0]
            if val < pad_range * (256 // pad_range):
                return (val % pad_range) + MIN_PADDING

    def _seal(self, aead_key: bytes, plaintext: bytes) -> bytes:
        """Seal with a fresh random nonce, timestamp and padding."""
        nonce = os.urandom(NONCE_SIZE)
        pad_len = self._sample_pad_len()
        padding = os.urandom(pad_len)
        timestamp_ms = int(time.time() * 1000)
        return _seal_deterministic(
            aead_key, self._suite, self._salt, nonce, timestamp_ms, pad_len, padding, plaintext
        )

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data with a standard AEAD and length obfuscation.

        Output (password mode): 0x03 || suite || salt(16) || nonce(12) || ct||tag
        Output (key mode):      0x13 || suite || nonce(12) || ct||tag

        The AEAD plaintext is timestamp_ms(8 LE) || pad_len(1) || padding || message;
        the AEAD additional data is every byte before the nonce.
        """
        return self._seal(self._aead_key, plaintext)

    def decrypt(self, encrypted: bytes) -> Optional[bytes]:
        """
        Decrypt and verify data, dispatching on the leading authenticated version
        byte. Returns plaintext, or None if authentication fails, the format is
        invalid, or the message is outside the freshness window.
        """
        if len(encrypted) < 1:
            return None

        version = encrypted[0]

        if version == VERSION_PASSWORD:
            aad_len = 2 + SALT_SIZE
            if len(encrypted) < aad_len + NONCE_SIZE + TAG_SIZE:
                return None
            if self._salt is None:
                # This instance is in pre-shared-key mode; cannot re-derive.
                return None
            suite = encrypted[1]
            salt = encrypted[2:2 + SALT_SIZE]
            master = self._derive_key(salt)
            aead_key = _derive_aead_key(master)

        elif version == VERSION_KEY:
            aad_len = 2
            if len(encrypted) < aad_len + NONCE_SIZE + TAG_SIZE:
                return None
            suite = encrypted[1]
            aead_key = self._aead_key

        else:
            return None

        return _open(aead_key, suite, encrypted, aad_len, self._max_age_ms)

    @property
    def key(self) -> bytes:
        """Get the derived master key (for testing/debugging)."""
        return self._key


def _seal_deterministic(
    aead_key: bytes,
    suite: int,
    salt: Optional[bytes],
    nonce: bytes,
    timestamp_ms: int,
    pad_len: int,
    padding: bytes,
    plaintext: bytes,
) -> bytes:
    """
    Deterministic AEAD seal over fully specified inputs (used for conformance
    vectors and wrapped by the randomized ``Shield._seal``).
    """
    aad = Shield._build_aad(suite, salt)
    inner = struct.pack("<Q", timestamp_ms) + bytes([pad_len]) + padding + plaintext
    aead = _aead_for_suite(suite, aead_key)
    if aead is None:
        raise ValueError(f"unknown cipher suite: {suite}")
    ct_and_tag = aead.encrypt(nonce, inner, aad)
    return aad + nonce + ct_and_tag


def _open(
    aead_key: bytes,
    suite: int,
    encrypted: bytes,
    aad_len: int,
    max_age_ms: Optional[int],
) -> Optional[bytes]:
    """Open an AEAD ciphertext, validate the inner layout and freshness window."""
    aead = _aead_for_suite(suite, aead_key)
    if aead is None:
        return None
    if len(encrypted) < aad_len + NONCE_SIZE + TAG_SIZE:
        return None

    aad = encrypted[:aad_len]
    nonce = encrypted[aad_len:aad_len + NONCE_SIZE]
    ct_and_tag = encrypted[aad_len + NONCE_SIZE:]

    try:
        inner = aead.decrypt(nonce, ct_and_tag, aad)
    except InvalidTag:
        return None

    # Inner layout: timestamp_ms(8 LE) || pad_len(1) || padding || message
    if len(inner) < INNER_HEADER_SIZE:
        return None
    timestamp_ms = struct.unpack("<Q", inner[:8])[0]
    pad_len = inner[8]
    if pad_len < MIN_PADDING or pad_len > MAX_PADDING:
        return None
    data_start = INNER_HEADER_SIZE + pad_len
    if len(inner) < data_start:
        return None

    # Freshness window (NOT full replay protection)
    if max_age_ms is not None:
        now_ms = int(time.time() * 1000)
        age = now_ms - timestamp_ms
        if timestamp_ms > now_ms + 5000 or age > max_age_ms:
            return None

    return inner[data_start:]


def quick_encrypt(key: bytes, data: bytes) -> bytes:
    """
    One-shot encrypt with a pre-shared key (no password derivation).

    Equivalent to ``Shield.with_key(key).encrypt(data)``: same authenticated,
    length-obfuscated v4 wire format (0x13 || suite || nonce || ct||tag) and the
    same HKDF-derived AEAD key as the instance API and the Rust source of truth.
    """
    return Shield.with_key(key).encrypt(data)


def quick_decrypt(key: bytes, encrypted: bytes) -> Optional[bytes]:
    """
    One-shot decrypt with a pre-shared key. Applies the default 60-second
    freshness window (matching the Rust source of truth).
    """
    return Shield.with_key(key).decrypt(encrypted)
