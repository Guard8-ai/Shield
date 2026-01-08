"""
API Protection Utilities for Shield

Provides rate limiting, token bucket, and API protection with encrypted state.

Usage:
    from shield.integrations import RateLimiter, TokenBucket, APIProtector

    # Rate limiter with encrypted counters
    limiter = RateLimiter(password="secret", service="api.example.com", max_requests=100, window=60)
    if limiter.is_allowed("user123"):
        # Process request
        pass

    # Token bucket for more flexible rate limiting
    bucket = TokenBucket(password="secret", service="api.example.com", capacity=10, refill_rate=1.0)
    if bucket.consume("user123"):
        # Process request
        pass

    # API protector combines multiple protection mechanisms
    protector = APIProtector(password="secret", service="api.example.com")
    protector.add_rate_limit(max_requests=100, window=60)
    protector.add_ip_whitelist(["10.0.0.0/8", "192.168.1.0/24"])
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from shield import Shield


@dataclass
class RateLimitState:
    """State for a rate limit window."""
    count: int = 0
    window_start: float = 0.0


class RateLimiter:
    """
    Rate limiter with encrypted state storage.

    Uses Shield encryption to protect rate limit counters, preventing
    tampering or state manipulation.

    Args:
        password: Encryption password
        service: Service identifier
        max_requests: Maximum requests per window
        window: Window size in seconds
        storage: Optional external storage backend

    Usage:
        limiter = RateLimiter(
            password="secret",
            service="api.example.com",
            max_requests=100,
            window=60
        )

        if limiter.is_allowed(user_id):
            process_request()
        else:
            return "Rate limit exceeded", 429
    """

    def __init__(
        self,
        password: str,
        service: str,
        max_requests: int = 100,
        window: int = 60,
        storage: Optional[Dict[str, bytes]] = None,
    ):
        self.shield = Shield(password, service)
        self.max_requests = max_requests
        self.window = window
        self.storage = storage if storage is not None else {}
        self._lock = threading.Lock()

    def _get_state(self, key: str) -> RateLimitState:
        """Get decrypted state for a key."""
        encrypted = self.storage.get(key)
        if not encrypted:
            return RateLimitState()

        try:
            decrypted = self.shield.decrypt(encrypted)
            data = json.loads(decrypted)
            return RateLimitState(
                count=data.get("count", 0),
                window_start=data.get("window_start", 0.0),
            )
        except Exception:
            return RateLimitState()

    def _set_state(self, key: str, state: RateLimitState) -> None:
        """Set encrypted state for a key."""
        data = json.dumps({
            "count": state.count,
            "window_start": state.window_start,
        }).encode("utf-8")
        self.storage[key] = self.shield.encrypt(data)

    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed under rate limit."""
        with self._lock:
            now = time.time()
            key = self._hash_key(identifier)
            state = self._get_state(key)

            # Reset window if expired
            if now - state.window_start >= self.window:
                state = RateLimitState(count=0, window_start=now)

            if state.count >= self.max_requests:
                return False

            state.count += 1
            self._set_state(key, state)
            return True

    def get_remaining(self, identifier: str) -> int:
        """Get remaining requests in current window."""
        with self._lock:
            now = time.time()
            key = self._hash_key(identifier)
            state = self._get_state(key)

            if now - state.window_start >= self.window:
                return self.max_requests

            return max(0, self.max_requests - state.count)

    def get_reset_time(self, identifier: str) -> float:
        """Get time until window resets."""
        with self._lock:
            now = time.time()
            key = self._hash_key(identifier)
            state = self._get_state(key)

            if now - state.window_start >= self.window:
                return 0.0

            return max(0.0, self.window - (now - state.window_start))

    def _hash_key(self, identifier: str) -> str:
        """Hash identifier to create storage key."""
        return hashlib.sha256(identifier.encode()).hexdigest()[:32]

    def reset(self, identifier: str) -> None:
        """Reset rate limit for an identifier."""
        with self._lock:
            key = self._hash_key(identifier)
            if key in self.storage:
                del self.storage[key]


@dataclass
class TokenBucketState:
    """State for a token bucket."""
    tokens: float = 0.0
    last_update: float = 0.0


class TokenBucket:
    """
    Token bucket rate limiter with encrypted state.

    Provides smoother rate limiting than fixed windows, allowing
    bursts while maintaining average rate.

    Args:
        password: Encryption password
        service: Service identifier
        capacity: Maximum bucket capacity (burst size)
        refill_rate: Tokens added per second
        storage: Optional external storage backend

    Usage:
        bucket = TokenBucket(
            password="secret",
            service="api.example.com",
            capacity=10,
            refill_rate=1.0  # 1 token per second
        )

        if bucket.consume(user_id):
            process_request()
        else:
            return "Too many requests", 429
    """

    def __init__(
        self,
        password: str,
        service: str,
        capacity: float = 10.0,
        refill_rate: float = 1.0,
        storage: Optional[Dict[str, bytes]] = None,
    ):
        self.shield = Shield(password, service)
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.storage = storage if storage is not None else {}
        self._lock = threading.Lock()

    def _get_state(self, key: str) -> TokenBucketState:
        """Get decrypted state for a key."""
        encrypted = self.storage.get(key)
        if not encrypted:
            return TokenBucketState(tokens=self.capacity, last_update=time.time())

        try:
            decrypted = self.shield.decrypt(encrypted)
            data = json.loads(decrypted)
            return TokenBucketState(
                tokens=data.get("tokens", self.capacity),
                last_update=data.get("last_update", time.time()),
            )
        except Exception:
            return TokenBucketState(tokens=self.capacity, last_update=time.time())

    def _set_state(self, key: str, state: TokenBucketState) -> None:
        """Set encrypted state for a key."""
        data = json.dumps({
            "tokens": state.tokens,
            "last_update": state.last_update,
        }).encode("utf-8")
        self.storage[key] = self.shield.encrypt(data)

    def consume(self, identifier: str, tokens: float = 1.0) -> bool:
        """Consume tokens from the bucket. Returns True if successful."""
        with self._lock:
            now = time.time()
            key = self._hash_key(identifier)
            state = self._get_state(key)

            # Refill tokens based on elapsed time
            elapsed = now - state.last_update
            state.tokens = min(self.capacity, state.tokens + elapsed * self.refill_rate)
            state.last_update = now

            if state.tokens >= tokens:
                state.tokens -= tokens
                self._set_state(key, state)
                return True

            self._set_state(key, state)
            return False

    def get_tokens(self, identifier: str) -> float:
        """Get current token count for an identifier."""
        with self._lock:
            now = time.time()
            key = self._hash_key(identifier)
            state = self._get_state(key)

            elapsed = now - state.last_update
            return min(self.capacity, state.tokens + elapsed * self.refill_rate)

    def wait_time(self, identifier: str, tokens: float = 1.0) -> float:
        """Calculate wait time until tokens are available."""
        current = self.get_tokens(identifier)
        if current >= tokens:
            return 0.0
        return (tokens - current) / self.refill_rate

    def _hash_key(self, identifier: str) -> str:
        """Hash identifier to create storage key."""
        return hashlib.sha256(identifier.encode()).hexdigest()[:32]

    def reset(self, identifier: str) -> None:
        """Reset bucket for an identifier."""
        with self._lock:
            key = self._hash_key(identifier)
            if key in self.storage:
                del self.storage[key]


class APIProtector:
    """
    Comprehensive API protection with multiple mechanisms.

    Combines rate limiting, IP filtering, request validation,
    and encrypted audit logging.

    Args:
        password: Encryption password
        service: Service identifier

    Usage:
        protector = APIProtector(password="secret", service="api.example.com")

        # Configure protections
        protector.add_rate_limit(max_requests=100, window=60)
        protector.add_ip_whitelist(["10.0.0.0/8"])
        protector.add_ip_blacklist(["1.2.3.4"])

        # Check request
        result = protector.check_request(client_ip="10.0.0.5", user_id="user123")
        if not result.allowed:
            return {"error": result.reason}, 403
    """

    @dataclass
    class CheckResult:
        """Result of a protection check."""
        allowed: bool
        reason: Optional[str] = None
        headers: Dict[str, str] = field(default_factory=dict)

    def __init__(self, password: str, service: str):
        self.shield = Shield(password, service)
        self.password = password
        self.service = service
        self.rate_limiter: Optional[RateLimiter] = None
        self.token_bucket: Optional[TokenBucket] = None
        self.ip_whitelist: Set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        self.ip_blacklist: Set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        self.require_whitelist = False
        self.audit_log: List[bytes] = []
        self._lock = threading.Lock()

    def add_rate_limit(
        self,
        max_requests: int = 100,
        window: int = 60,
        storage: Optional[Dict[str, bytes]] = None,
    ) -> "APIProtector":
        """Add rate limiting protection."""
        self.rate_limiter = RateLimiter(
            password=self.password,
            service=self.service,
            max_requests=max_requests,
            window=window,
            storage=storage,
        )
        return self

    def add_token_bucket(
        self,
        capacity: float = 10.0,
        refill_rate: float = 1.0,
        storage: Optional[Dict[str, bytes]] = None,
    ) -> "APIProtector":
        """Add token bucket rate limiting."""
        self.token_bucket = TokenBucket(
            password=self.password,
            service=self.service,
            capacity=capacity,
            refill_rate=refill_rate,
            storage=storage,
        )
        return self

    def add_ip_whitelist(
        self,
        networks: List[str],
        require: bool = False,
    ) -> "APIProtector":
        """Add IP whitelist. If require=True, only whitelisted IPs allowed."""
        for network in networks:
            try:
                self.ip_whitelist.add(ipaddress.ip_network(network, strict=False))
            except ValueError:
                pass  # Skip invalid networks
        self.require_whitelist = require
        return self

    def add_ip_blacklist(self, networks: List[str]) -> "APIProtector":
        """Add IP blacklist."""
        for network in networks:
            try:
                self.ip_blacklist.add(ipaddress.ip_network(network, strict=False))
            except ValueError:
                pass
        return self

    def check_request(
        self,
        client_ip: Optional[str] = None,
        user_id: Optional[str] = None,
        request_data: Optional[dict] = None,
    ) -> CheckResult:
        """Check if request is allowed."""
        headers: Dict[str, str] = {}

        # IP blacklist check
        if client_ip:
            try:
                ip = ipaddress.ip_address(client_ip)
                for network in self.ip_blacklist:
                    if ip in network:
                        self._log_event("blocked", client_ip, user_id, "IP blacklisted")
                        return self.CheckResult(
                            allowed=False,
                            reason="IP address blocked",
                        )
            except ValueError:
                pass

        # IP whitelist check
        if self.require_whitelist and client_ip:
            try:
                ip = ipaddress.ip_address(client_ip)
                whitelisted = any(ip in network for network in self.ip_whitelist)
                if not whitelisted:
                    self._log_event("blocked", client_ip, user_id, "IP not whitelisted")
                    return self.CheckResult(
                        allowed=False,
                        reason="IP address not authorized",
                    )
            except ValueError:
                return self.CheckResult(
                    allowed=False,
                    reason="Invalid IP address",
                )

        # Rate limit check
        identifier = user_id or client_ip or "anonymous"

        if self.rate_limiter:
            if not self.rate_limiter.is_allowed(identifier):
                remaining = self.rate_limiter.get_remaining(identifier)
                reset_time = self.rate_limiter.get_reset_time(identifier)
                self._log_event("rate_limited", client_ip, user_id, "Rate limit exceeded")
                return self.CheckResult(
                    allowed=False,
                    reason="Rate limit exceeded",
                    headers={
                        "X-RateLimit-Limit": str(self.rate_limiter.max_requests),
                        "X-RateLimit-Remaining": str(remaining),
                        "X-RateLimit-Reset": str(int(reset_time)),
                    },
                )
            headers["X-RateLimit-Remaining"] = str(
                self.rate_limiter.get_remaining(identifier)
            )

        if self.token_bucket:
            if not self.token_bucket.consume(identifier):
                wait = self.token_bucket.wait_time(identifier)
                self._log_event("throttled", client_ip, user_id, "Token bucket empty")
                return self.CheckResult(
                    allowed=False,
                    reason="Too many requests",
                    headers={
                        "Retry-After": str(int(wait) + 1),
                    },
                )

        self._log_event("allowed", client_ip, user_id, None)
        return self.CheckResult(allowed=True, headers=headers)

    def _log_event(
        self,
        action: str,
        client_ip: Optional[str],
        user_id: Optional[str],
        reason: Optional[str],
    ) -> None:
        """Log an event with encryption."""
        with self._lock:
            event = {
                "timestamp": time.time(),
                "action": action,
                "client_ip": client_ip,
                "user_id": user_id,
                "reason": reason,
            }
            encrypted = self.shield.encrypt(json.dumps(event).encode("utf-8"))
            self.audit_log.append(encrypted)

            # Keep only last 1000 events
            if len(self.audit_log) > 1000:
                self.audit_log = self.audit_log[-1000:]

    def get_audit_log(self, limit: int = 100) -> List[dict]:
        """Get decrypted audit log entries."""
        with self._lock:
            entries = []
            for encrypted in self.audit_log[-limit:]:
                try:
                    decrypted = self.shield.decrypt(encrypted)
                    entries.append(json.loads(decrypted))
                except Exception:
                    pass
            return entries

    def clear_audit_log(self) -> None:
        """Clear the audit log."""
        with self._lock:
            self.audit_log.clear()
