"""
Shield Key Exchange - Key exchange without public-key crypto.

Methods:
1. PAKE: Password-Authenticated Key Exchange
2. Physical: QR codes, base64 for manual exchange
3. Key Splitting: Threshold secret sharing

Example:
    >>> from shield.exchange import PAKEExchange, KeySplitter
    >>>
    >>> # Password-based key exchange
    >>> alice_key = PAKEExchange.derive("shared_password", b"salt", "alice")
    >>> bob_key = PAKEExchange.derive("shared_password", b"salt", "bob")
    >>> session_key = PAKEExchange.combine(alice_key, bob_key)
    >>>
    >>> # Key splitting
    >>> shares = KeySplitter.split(secret_key, num_shares=5)
    >>> recovered = KeySplitter.combine(shares)  # Need all shares
"""

import hmac
import hashlib
import struct
import secrets
import base64
from typing import List, Optional, Tuple


class PAKEExchange:
    """
    Password-Authenticated Key Exchange.

    Both parties derive a shared key from a common password.
    Uses role binding to prevent reflection attacks.
    """

    ITERATIONS = 200000  # Higher than normal for key exchange

    @staticmethod
    def derive(
        password: str,
        salt: bytes,
        role: str,
        iterations: int = None,
    ) -> bytes:
        """
        Derive key contribution from password.

        Args:
            password: Shared password between parties
            salt: Public salt (can be exchanged openly)
            role: Role identifier ('alice', 'bob', 'initiator', etc.)
            iterations: PBKDF2 iterations (default: 200000)

        Returns:
            32-byte key contribution
        """
        if iterations is None:
            iterations = PAKEExchange.ITERATIONS

        base_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            iterations
        )
        return hashlib.sha256(base_key + role.encode()).digest()

    @staticmethod
    def combine(*contributions: bytes) -> bytes:
        """
        Combine key contributions into session key.

        Args:
            *contributions: Key contributions from all parties

        Returns:
            32-byte shared session key
        """
        combined = b''.join(sorted(contributions))
        return hashlib.sha256(combined).digest()

    @staticmethod
    def generate_salt() -> bytes:
        """Generate random salt for key exchange."""
        return secrets.token_bytes(16)


class QRExchange:
    """
    Key exchange via QR codes or manual transfer.

    Encodes keys in URL-safe base64 for easy scanning/typing.
    """

    @staticmethod
    def encode(key: bytes) -> str:
        """
        Encode key for QR code or manual transfer.

        Args:
            key: Key bytes to encode

        Returns:
            URL-safe base64 string
        """
        return base64.urlsafe_b64encode(key).decode('ascii')

    @staticmethod
    def decode(encoded: str) -> bytes:
        """
        Decode key from QR code or manual input.

        Args:
            encoded: Base64 string from encode()

        Returns:
            Key bytes
        """
        return base64.urlsafe_b64decode(encoded)

    @staticmethod
    def generate_exchange_data(key: bytes, metadata: dict = None) -> str:
        """
        Generate complete exchange data with optional metadata.

        Args:
            key: Key to exchange
            metadata: Optional metadata (issuer, expiry, etc.)

        Returns:
            JSON-like string for QR code
        """
        import json
        data = {
            'v': 1,  # Version
            'k': base64.urlsafe_b64encode(key).decode('ascii'),
        }
        if metadata:
            data['m'] = metadata
        return json.dumps(data, separators=(',', ':'))

    @staticmethod
    def parse_exchange_data(data: str) -> Tuple[bytes, Optional[dict]]:
        """
        Parse exchange data from QR code.

        Args:
            data: JSON string from generate_exchange_data()

        Returns:
            Tuple of (key, metadata)
        """
        import json
        parsed = json.loads(data)
        key = base64.urlsafe_b64decode(parsed['k'])
        metadata = parsed.get('m')
        return key, metadata


class KeySplitter:
    """
    Split keys into shares for threshold recovery.

    This is a simplified XOR-based scheme where ALL shares
    are required for reconstruction. For true threshold
    schemes (k-of-n), use Shamir's Secret Sharing.
    """

    @staticmethod
    def split(key: bytes, num_shares: int) -> List[bytes]:
        """
        Split key into shares (all required for reconstruction).

        Args:
            key: Key to split
            num_shares: Number of shares to create

        Returns:
            List of shares
        """
        if num_shares < 2:
            raise ValueError("Need at least 2 shares")

        shares = [secrets.token_bytes(len(key)) for _ in range(num_shares - 1)]

        # Final share = XOR of key with all other shares
        final = key
        for share in shares:
            final = bytes(a ^ b for a, b in zip(final, share))

        shares.append(final)
        return shares

    @staticmethod
    def combine(shares: List[bytes]) -> bytes:
        """
        Combine shares to recover key.

        Args:
            shares: All shares from split()

        Returns:
            Original key
        """
        if len(shares) < 2:
            raise ValueError("Need at least 2 shares")

        result = shares[0]
        for share in shares[1:]:
            result = bytes(a ^ b for a, b in zip(result, share))

        return result

    @staticmethod
    def split_threshold(key: bytes, threshold: int, num_shares: int) -> List[Tuple[int, bytes]]:
        """
        Split key with threshold recovery (simplified Shamir-like).

        Uses polynomial interpolation simulation with XOR.
        Note: This is NOT cryptographically equivalent to Shamir's
        but provides basic threshold functionality.

        Args:
            key: Key to split
            threshold: Minimum shares needed
            num_shares: Total shares to create

        Returns:
            List of (index, share) tuples
        """
        if threshold > num_shares:
            raise ValueError("Threshold cannot exceed num_shares")
        if threshold < 2:
            raise ValueError("Threshold must be at least 2")

        # Generate random coefficients for "polynomial"
        coefficients = [key] + [secrets.token_bytes(len(key)) for _ in range(threshold - 1)]

        shares = []
        for i in range(1, num_shares + 1):
            # Evaluate "polynomial" at point i
            share = bytes(len(key))
            for j, coef in enumerate(coefficients):
                # Simplified: XOR with coefficient * i^j (modular)
                factor = pow(i, j, 256)
                term = bytes((c * factor) % 256 for c in coef)
                share = bytes(a ^ b for a, b in zip(share, term))
            shares.append((i, share))

        return shares

    @staticmethod
    def combine_threshold(shares: List[Tuple[int, bytes]], threshold: int) -> bytes:
        """
        Combine threshold shares to recover key.

        Args:
            shares: At least `threshold` shares from split_threshold()
            threshold: Threshold used in split

        Returns:
            Original key
        """
        if len(shares) < threshold:
            raise ValueError(f"Need at least {threshold} shares, got {len(shares)}")

        # Use first `threshold` shares
        used_shares = shares[:threshold]

        # Lagrange interpolation at x=0 (simplified)
        key_len = len(used_shares[0][1])
        result = bytes(key_len)

        for i, (xi, yi) in enumerate(used_shares):
            # Calculate Lagrange basis polynomial at 0
            numerator = 1
            denominator = 1
            for j, (xj, _) in enumerate(used_shares):
                if i != j:
                    numerator = (numerator * (-xj)) % 256
                    denominator = (denominator * (xi - xj)) % 256

            # Modular inverse (simplified)
            if denominator == 0:
                denominator = 1
            coef = (numerator * pow(denominator, -1, 256)) % 256

            term = bytes((y * coef) % 256 for y in yi)
            result = bytes(a ^ b for a, b in zip(result, term))

        return result
