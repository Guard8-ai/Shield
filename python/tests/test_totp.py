"""Tests for Shield TOTP (2FA)."""

import time
import pytest
from shield.totp import TOTP, RecoveryCodes


class TestTOTP:
    """Test TOTP class."""

    def test_generate_verify(self):
        """Generate and verify TOTP code."""
        secret = TOTP.generate_secret()
        totp = TOTP(secret)
        code = totp.generate()
        assert totp.verify(code)

    def test_code_length(self):
        """Code is correct length."""
        secret = TOTP.generate_secret()
        totp = TOTP(secret, digits=6)
        code = totp.generate()
        assert len(code) == 6
        assert code.isdigit()

    def test_code_length_8(self):
        """8-digit codes work."""
        secret = TOTP.generate_secret()
        totp = TOTP(secret, digits=8)
        code = totp.generate()
        assert len(code) == 8

    def test_wrong_code_fails(self):
        """Wrong code returns False."""
        secret = TOTP.generate_secret()
        totp = TOTP(secret)
        assert not totp.verify("000000")

    def test_time_window(self):
        """Codes valid within time window."""
        secret = TOTP.generate_secret()
        totp = TOTP(secret, interval=30)
        now = int(time.time())

        # Generate code for 30 seconds ago
        old_code = totp.generate(now - 30)

        # Should still verify with window=1
        assert totp.verify(old_code, now, window=1)

    def test_expired_code_fails(self):
        """Very old codes fail."""
        secret = TOTP.generate_secret()
        totp = TOTP(secret, interval=30)
        now = int(time.time())

        # Generate code for 2 minutes ago
        old_code = totp.generate(now - 120)

        # Should fail with window=1 (only checks ±1 interval)
        assert not totp.verify(old_code, now, window=1)

    def test_secret_base32_roundtrip(self):
        """Base32 encoding/decoding roundtrip."""
        secret = TOTP.generate_secret()
        b32 = TOTP.secret_to_base32(secret)
        decoded = TOTP.secret_from_base32(b32)
        assert decoded == secret

    def test_base32_no_padding(self):
        """Base32 output has no padding."""
        secret = TOTP.generate_secret()
        b32 = TOTP.secret_to_base32(secret)
        assert "=" not in b32

    def test_base32_accepts_lowercase(self):
        """Base32 decoder accepts lowercase."""
        secret = TOTP.generate_secret()
        b32 = TOTP.secret_to_base32(secret).lower()
        decoded = TOTP.secret_from_base32(b32)
        assert decoded == secret

    def test_provisioning_uri(self):
        """Provisioning URI is valid."""
        secret = TOTP.generate_secret()
        totp = TOTP(secret)
        uri = totp.provisioning_uri("user@example.com", "MyApp")

        assert uri.startswith("otpauth://totp/")
        assert "MyApp:user@example.com" in uri
        assert "secret=" in uri
        assert "issuer=MyApp" in uri

    def test_sha256_algorithm(self):
        """SHA256 algorithm works."""
        secret = TOTP.generate_secret()
        totp = TOTP(secret, algorithm="sha256")
        code = totp.generate()
        assert totp.verify(code)

    def test_known_vector(self):
        """Test with known test vector."""
        # Standard test vector from RFC 6238
        secret = b"12345678901234567890"  # 20 bytes
        totp = TOTP(secret, digits=8)

        # Test vector: T = 59 seconds, expected code = 94287082
        code = totp.generate(59)
        assert code == "94287082"


class TestRecoveryCodes:
    """Test RecoveryCodes class."""

    def test_generate_codes(self):
        """Generate recovery codes."""
        codes = RecoveryCodes.generate_codes()
        assert len(codes) == 10
        for code in codes:
            assert len(code) == 9  # XXXX-XXXX format
            assert "-" in code

    def test_verify_code(self):
        """Verify recovery code."""
        rc = RecoveryCodes()
        codes = rc.codes
        assert rc.verify(codes[0])

    def test_code_consumed(self):
        """Codes can only be used once."""
        rc = RecoveryCodes()
        code = rc.codes[0]
        assert rc.verify(code)
        assert not rc.verify(code)  # Second use fails

    def test_remaining_count(self):
        """Remaining count decreases."""
        rc = RecoveryCodes()
        assert rc.remaining == 10

        rc.verify(rc.codes[0])
        assert rc.remaining == 9

    def test_wrong_code_fails(self):
        """Wrong codes fail."""
        rc = RecoveryCodes()
        assert not rc.verify("XXXX-XXXX")

    def test_normalize_format(self):
        """Various input formats work."""
        rc = RecoveryCodes()
        code = rc.codes[0]

        # Remove dash
        no_dash = code.replace("-", "")
        assert rc.verify(no_dash)

    def test_case_insensitive(self):
        """Codes are case-insensitive."""
        rc = RecoveryCodes()
        code = rc.codes[0].lower()
        assert rc.verify(code)

    def test_custom_count(self):
        """Custom code count works."""
        codes = RecoveryCodes.generate_codes(count=5)
        assert len(codes) == 5

    def test_existing_codes(self):
        """Initialize with existing codes."""
        existing = ["AAAA-BBBB", "CCCC-DDDD"]
        rc = RecoveryCodes(existing)
        assert rc.remaining == 2
        assert rc.verify("AAAA-BBBB")
        assert rc.remaining == 1
