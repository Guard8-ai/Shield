"""Tests for Shield integrations - FastAPI, Flask, Protection, and Browser helpers."""

import base64
import json
import time
import pytest
from shield.integrations.protection import RateLimiter, TokenBucket, APIProtector
from shield.integrations.browser import BrowserBridge, EncryptedCookie, SecureCORS, CookieOptions


class TestRateLimiter:
    """Test RateLimiter class."""

    def test_allows_under_limit(self):
        """Requests under limit are allowed."""
        limiter = RateLimiter("password", "service", max_requests=5, window=60)
        for _ in range(5):
            assert limiter.is_allowed("user1")

    def test_blocks_over_limit(self):
        """Requests over limit are blocked."""
        limiter = RateLimiter("password", "service", max_requests=3, window=60)
        for _ in range(3):
            assert limiter.is_allowed("user1")
        assert not limiter.is_allowed("user1")

    def test_different_users_separate_limits(self):
        """Different users have separate limits."""
        limiter = RateLimiter("password", "service", max_requests=2, window=60)
        assert limiter.is_allowed("user1")
        assert limiter.is_allowed("user1")
        assert not limiter.is_allowed("user1")
        # User2 still has full quota
        assert limiter.is_allowed("user2")
        assert limiter.is_allowed("user2")

    def test_get_remaining(self):
        """Get remaining requests in window."""
        limiter = RateLimiter("password", "service", max_requests=5, window=60)
        assert limiter.get_remaining("user1") == 5
        limiter.is_allowed("user1")
        limiter.is_allowed("user1")
        assert limiter.get_remaining("user1") == 3

    def test_reset(self):
        """Reset clears rate limit for user."""
        limiter = RateLimiter("password", "service", max_requests=1, window=60)
        assert limiter.is_allowed("user1")
        assert not limiter.is_allowed("user1")
        limiter.reset("user1")
        assert limiter.is_allowed("user1")

    def test_encrypted_storage(self):
        """State is stored encrypted."""
        storage = {}
        limiter = RateLimiter("password", "service", max_requests=5, window=60, storage=storage)
        limiter.is_allowed("user1")
        # Storage should have encrypted data
        assert len(storage) == 1
        key = list(storage.keys())[0]
        # Verify data is encrypted (should not be valid JSON)
        try:
            json.loads(storage[key])
            pytest.fail("Storage should be encrypted")
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass  # Expected - data is encrypted


class TestTokenBucket:
    """Test TokenBucket class."""

    def test_consume_available(self):
        """Can consume when tokens available."""
        bucket = TokenBucket("password", "service", capacity=5, refill_rate=1.0)
        for _ in range(5):
            assert bucket.consume("user1")

    def test_blocks_when_empty(self):
        """Blocks when bucket is empty."""
        bucket = TokenBucket("password", "service", capacity=2, refill_rate=0.0)
        assert bucket.consume("user1")
        assert bucket.consume("user1")
        assert not bucket.consume("user1")

    def test_refill_over_time(self):
        """Tokens refill over time."""
        bucket = TokenBucket("password", "service", capacity=2, refill_rate=10.0)  # Fast refill
        assert bucket.consume("user1")
        assert bucket.consume("user1")
        assert not bucket.consume("user1")
        # Wait for refill
        time.sleep(0.15)
        assert bucket.consume("user1")

    def test_get_tokens(self):
        """Get current token count."""
        bucket = TokenBucket("password", "service", capacity=5, refill_rate=1.0)
        assert bucket.get_tokens("user1") >= 4.9  # Account for timing
        bucket.consume("user1", 2)
        assert bucket.get_tokens("user1") >= 2.9

    def test_consume_multiple(self):
        """Can consume multiple tokens at once."""
        bucket = TokenBucket("password", "service", capacity=10, refill_rate=0.0)
        assert bucket.consume("user1", 5)
        assert bucket.consume("user1", 5)
        assert not bucket.consume("user1", 1)

    def test_wait_time(self):
        """Calculate wait time for tokens."""
        # Use 0 refill rate to avoid timing complications
        bucket = TokenBucket("password", "service", capacity=10, refill_rate=0.0)
        # When bucket is full, wait_time should be 0
        assert bucket.wait_time("user1", 5) == 0.0
        # Consume all tokens
        bucket.consume("user1", 5)
        bucket.consume("user1", 5)
        # Now wait_time for any amount should be inf (0 refill rate)
        # Actually with 0 refill, wait_time would try to divide by 0
        # Let's use a small refill rate instead
        bucket2 = TokenBucket("password", "service", capacity=10, refill_rate=0.1)
        bucket2.consume("user2", 5)  # Consume 5, leaving ~5
        bucket2.consume("user2", 5)  # Consume 5, leaving ~0
        # Now we need 5 tokens at 0.1/second = 50 seconds minimum
        wait = bucket2.wait_time("user2", 5)
        assert wait > 40  # Should be around 50 seconds, allow variance


class TestAPIProtector:
    """Test APIProtector class."""

    def test_allows_by_default(self):
        """Allows requests by default."""
        protector = APIProtector("password", "service")
        result = protector.check_request(client_ip="1.2.3.4")
        assert result.allowed

    def test_rate_limit_integration(self):
        """Rate limiting works via protector."""
        protector = APIProtector("password", "service")
        protector.add_rate_limit(max_requests=2, window=60)
        assert protector.check_request(user_id="user1").allowed
        assert protector.check_request(user_id="user1").allowed
        result = protector.check_request(user_id="user1")
        assert not result.allowed
        assert "Rate limit" in result.reason

    def test_ip_blacklist(self):
        """IP blacklist blocks requests."""
        protector = APIProtector("password", "service")
        protector.add_ip_blacklist(["1.2.3.0/24"])
        result = protector.check_request(client_ip="1.2.3.50")
        assert not result.allowed
        assert "blocked" in result.reason

    def test_ip_whitelist_required(self):
        """IP whitelist blocks non-whitelisted IPs when required."""
        protector = APIProtector("password", "service")
        protector.add_ip_whitelist(["10.0.0.0/8"], require=True)
        # Whitelisted IP allowed
        assert protector.check_request(client_ip="10.0.0.1").allowed
        # Non-whitelisted blocked
        result = protector.check_request(client_ip="1.2.3.4")
        assert not result.allowed

    def test_audit_log(self):
        """Audit log records events."""
        protector = APIProtector("password", "service")
        protector.check_request(client_ip="1.2.3.4", user_id="user1")
        protector.check_request(client_ip="5.6.7.8", user_id="user2")
        log = protector.get_audit_log()
        assert len(log) == 2
        assert log[0]["action"] == "allowed"
        assert log[0]["user_id"] == "user1"


class TestBrowserBridge:
    """Test BrowserBridge class."""

    def test_generate_client_key(self):
        """Generate client key with metadata."""
        bridge = BrowserBridge("password", "service")
        key_info = bridge.generate_client_key("session123", ttl=3600)
        assert "key" in key_info
        assert key_info["session_id"] == "session123"
        assert key_info["algorithm"] == "shield-v1"
        assert "expires_at" in key_info

    def test_encrypt_decrypt_for_client(self):
        """Encrypt and decrypt for client session."""
        bridge = BrowserBridge("password", "service")
        bridge.generate_client_key("session123")
        data = b"secret data"
        encrypted = bridge.encrypt_for_client("session123", data)
        decrypted = bridge.decrypt_from_client("session123", encrypted)
        assert decrypted == data

    def test_session_validity(self):
        """Session validity check works."""
        bridge = BrowserBridge("password", "service")
        assert not bridge.is_session_valid("nonexistent")
        bridge.generate_client_key("session123", ttl=1)
        assert bridge.is_session_valid("session123")

    def test_revoke_session(self):
        """Revoke session removes it."""
        bridge = BrowserBridge("password", "service")
        bridge.generate_client_key("session123")
        assert bridge.is_session_valid("session123")
        bridge.revoke_session("session123")
        assert not bridge.is_session_valid("session123")


class TestEncryptedCookie:
    """Test EncryptedCookie class."""

    def test_encode_decode(self):
        """Encode and decode cookie value."""
        cookie = EncryptedCookie("password", "service")
        data = {"user_id": "123", "role": "admin"}
        encoded = cookie.encode(data)
        decoded = cookie.decode(encoded)
        assert decoded == data

    def test_expired_cookie_returns_none(self):
        """Expired cookie returns None."""
        options = CookieOptions(max_age=1)  # Expires in 1 second
        cookie = EncryptedCookie("password", "service", options)
        encoded = cookie.encode({"user_id": "123"})
        time.sleep(1.5)  # Wait for expiration
        assert cookie.decode(encoded) is None

    def test_tampered_cookie_returns_none(self):
        """Tampered cookie returns None."""
        cookie = EncryptedCookie("password", "service")
        encoded = cookie.encode({"user_id": "123"})
        # Tamper with the value
        tampered = encoded[:-5] + "XXXXX"
        assert cookie.decode(tampered) is None

    def test_make_header(self):
        """Make complete Set-Cookie header."""
        cookie = EncryptedCookie("password", "service")
        header = cookie.make_header("session", {"user_id": "123"})
        assert header.startswith("session=")
        assert "Secure" in header
        assert "HttpOnly" in header
        assert "SameSite=Strict" in header

    def test_parse_header(self):
        """Parse Cookie header."""
        cookie = EncryptedCookie("password", "service")
        value = cookie.encode({"user_id": "123"})
        cookie_header = f"session={value}; other=value"
        data = cookie.parse_header(cookie_header, "session")
        assert data == {"user_id": "123"}


class TestSecureCORS:
    """Test SecureCORS class."""

    def test_allowed_origin(self):
        """Allowed origin gets headers."""
        cors = SecureCORS(
            allowed_origins=["https://app.example.com"],
            password="password",
            service="service"
        )
        headers = cors.get_headers("https://app.example.com")
        assert headers["Access-Control-Allow-Origin"] == "https://app.example.com"
        assert headers["Access-Control-Allow-Credentials"] == "true"

    def test_disallowed_origin(self):
        """Disallowed origin gets no headers."""
        cors = SecureCORS(
            allowed_origins=["https://app.example.com"],
            password="password",
            service="service"
        )
        headers = cors.get_headers("https://evil.com")
        assert len(headers) == 0

    def test_wildcard_origin(self):
        """Wildcard allows any origin."""
        cors = SecureCORS(
            allowed_origins=["*"],
            password="password",
            service="service",
            allow_credentials=False
        )
        headers = cors.get_headers("https://any.com")
        assert headers["Access-Control-Allow-Origin"] == "*"

    def test_preflight_response(self):
        """Preflight response includes methods and headers."""
        cors = SecureCORS(
            allowed_origins=["https://app.example.com"],
            password="password",
            service="service"
        )
        headers = cors.preflight_response("https://app.example.com")
        assert "Access-Control-Allow-Methods" in headers
        assert "Access-Control-Allow-Headers" in headers
        assert "Access-Control-Max-Age" in headers

    def test_sign_verify_request(self):
        """Sign and verify request."""
        cors = SecureCORS(
            allowed_origins=["https://app.example.com"],
            password="password",
            service="service"
        )
        origin = "https://app.example.com"
        signature = cors.sign_request(origin)
        assert cors.verify_request(origin, signature)

    def test_verify_expired_signature(self):
        """Expired signature fails verification."""
        cors = SecureCORS(
            allowed_origins=["https://app.example.com"],
            password="password",
            service="service"
        )
        origin = "https://app.example.com"
        # Sign with old timestamp
        old_ts = int(time.time()) - 400  # 400 seconds ago
        signature = cors.sign_request(origin, old_ts)
        assert not cors.verify_request(origin, signature, max_age=300)

    def test_add_remove_origin(self):
        """Add and remove origins dynamically."""
        cors = SecureCORS(
            allowed_origins=["https://app.example.com"],
            password="password",
            service="service"
        )
        assert not cors.is_origin_allowed("https://new.example.com")
        cors.add_origin("https://new.example.com")
        assert cors.is_origin_allowed("https://new.example.com")
        cors.remove_origin("https://new.example.com")
        assert not cors.is_origin_allowed("https://new.example.com")
