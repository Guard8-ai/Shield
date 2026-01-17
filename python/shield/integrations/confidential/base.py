"""
Base Attestation Types for Confidential Computing

Provides abstract base classes and common types for TEE attestation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from shield import Shield


class TEEType(Enum):
    """Supported Trusted Execution Environment types."""
    NITRO = "aws_nitro"
    SEV_SNP = "gcp_sev_snp"
    MAA = "azure_maa"
    SGX = "intel_sgx"
    UNKNOWN = "unknown"


class AttestationError(Exception):
    """Raised when attestation verification fails."""

    def __init__(self, message: str, code: str = "ATTESTATION_FAILED"):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class AttestationResult:
    """Result of attestation verification."""
    verified: bool
    tee_type: TEEType
    measurements: Dict[str, str] = field(default_factory=dict)
    claims: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    error: Optional[str] = None
    raw_evidence: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "verified": self.verified,
            "tee_type": self.tee_type.value,
            "measurements": self.measurements,
            "claims": self.claims,
            "timestamp": self.timestamp,
            "error": self.error,
        }


class AttestationProvider(ABC):
    """Abstract base class for attestation providers."""

    @property
    @abstractmethod
    def tee_type(self) -> TEEType:
        """Return the TEE type this provider handles."""
        pass

    @abstractmethod
    async def verify(self, evidence: bytes) -> AttestationResult:
        """
        Verify attestation evidence.

        Args:
            evidence: Raw attestation evidence (format depends on TEE type)

        Returns:
            AttestationResult with verification status and claims

        Raises:
            AttestationError: If verification fails
        """
        pass

    @abstractmethod
    async def generate_evidence(self, user_data: Optional[bytes] = None) -> bytes:
        """
        Generate attestation evidence for this TEE.

        Args:
            user_data: Optional user data to include in attestation

        Returns:
            Raw attestation evidence bytes

        Raises:
            AttestationError: If not running in a supported TEE
        """
        pass

    def verify_measurements(
        self,
        result: AttestationResult,
        expected: Dict[str, str],
    ) -> bool:
        """
        Verify that measurements match expected values.

        Args:
            result: Attestation result to check
            expected: Dictionary of measurement name -> expected value

        Returns:
            True if all expected measurements match
        """
        for name, expected_value in expected.items():
            actual = result.measurements.get(name)
            if actual is None or actual.lower() != expected_value.lower():
                return False
        return True


@dataclass
class KeyReleasePolicy:
    """Policy for releasing keys based on attestation."""
    required_tee_types: List[TEEType] = field(default_factory=list)
    required_measurements: Dict[str, str] = field(default_factory=dict)
    max_age_seconds: float = 300.0
    allowed_claims: Dict[str, List[str]] = field(default_factory=dict)

    def evaluate(self, result: AttestationResult) -> bool:
        """Evaluate if attestation result satisfies this policy."""
        if not result.verified:
            return False

        if self.required_tee_types:
            if result.tee_type not in self.required_tee_types:
                return False

        age = time.time() - result.timestamp
        if age > self.max_age_seconds:
            return False

        for name, expected in self.required_measurements.items():
            actual = result.measurements.get(name)
            if actual is None or actual.lower() != expected.lower():
                return False

        for claim_name, allowed_values in self.allowed_claims.items():
            actual = result.claims.get(claim_name)
            if actual not in allowed_values:
                return False

        return True


class TEEKeyManager:
    """
    TEE-aware key manager with attestation-gated key release.

    Keys are only released after successful attestation verification
    against a configurable policy.

    Usage:
        provider = NitroAttestationProvider()
        key_manager = TEEKeyManager(
            password="secret",
            service="api.example.com",
            provider=provider,
        )

        # Set release policy
        key_manager.set_policy(KeyReleasePolicy(
            required_tee_types=[TEEType.NITRO],
            required_measurements={"PCR0": "abc123..."},
        ))

        # Get key (requires valid attestation)
        key = await key_manager.get_key(attestation_evidence)
    """

    def __init__(
        self,
        password: str,
        service: str,
        provider: AttestationProvider,
        policy: Optional[KeyReleasePolicy] = None,
    ):
        self.shield = Shield(password, service)
        self.provider = provider
        self.policy = policy or KeyReleasePolicy()
        self._key_cache: Dict[str, tuple[bytes, float]] = {}
        self._cache_ttl = 60.0

    def set_policy(self, policy: KeyReleasePolicy) -> None:
        """Set the key release policy."""
        self.policy = policy

    async def get_key(
        self,
        attestation_evidence: bytes,
        key_id: str = "default",
    ) -> bytes:
        """
        Get a key after verifying attestation.

        Args:
            attestation_evidence: Raw attestation evidence
            key_id: Identifier for the key to retrieve

        Returns:
            Derived key bytes

        Raises:
            AttestationError: If attestation fails or policy not satisfied
        """
        cache_key = self._hash_evidence(attestation_evidence, key_id)
        cached = self._key_cache.get(cache_key)
        if cached:
            key, timestamp = cached
            if time.time() - timestamp < self._cache_ttl:
                return key

        result = await self.provider.verify(attestation_evidence)

        if not self.policy.evaluate(result):
            raise AttestationError(
                "Attestation does not satisfy key release policy",
                code="POLICY_VIOLATION",
            )

        key = self._derive_key(key_id, result)
        self._key_cache[cache_key] = (key, time.time())

        return key

    def _derive_key(self, key_id: str, result: AttestationResult) -> bytes:
        """Derive a key bound to the attestation result."""
        binding_data = json.dumps({
            "key_id": key_id,
            "tee_type": result.tee_type.value,
            "measurements": result.measurements,
        }, sort_keys=True).encode()

        combined = binding_data + self.shield._key
        return hashlib.sha256(combined).digest()

    def _hash_evidence(self, evidence: bytes, key_id: str) -> str:
        """Hash evidence for cache key."""
        h = hashlib.sha256()
        h.update(evidence)
        h.update(key_id.encode())
        return h.hexdigest()[:32]

    async def encrypt_for_tee(
        self,
        data: bytes,
        attestation_evidence: bytes,
    ) -> bytes:
        """
        Encrypt data that can only be decrypted by an attested TEE.

        Args:
            data: Data to encrypt
            attestation_evidence: Attestation evidence of target TEE

        Returns:
            Encrypted data with attestation binding
        """
        key = await self.get_key(attestation_evidence, "encryption")
        temp_shield = Shield.__new__(Shield)
        temp_shield._key = key
        temp_shield._service = self.shield._service

        encrypted = temp_shield.encrypt(data)

        result = await self.provider.verify(attestation_evidence)
        envelope = {
            "encrypted": base64.b64encode(encrypted).decode(),
            "tee_type": result.tee_type.value,
            "measurements": result.measurements,
        }

        return json.dumps(envelope).encode()

    async def decrypt_in_tee(
        self,
        envelope_data: bytes,
        attestation_evidence: bytes,
    ) -> bytes:
        """
        Decrypt data inside an attested TEE.

        Args:
            envelope_data: Encrypted envelope from encrypt_for_tee
            attestation_evidence: Current TEE's attestation evidence

        Returns:
            Decrypted data

        Raises:
            AttestationError: If TEE doesn't match or attestation fails
        """
        envelope = json.loads(envelope_data)

        result = await self.provider.verify(attestation_evidence)

        if result.tee_type.value != envelope["tee_type"]:
            raise AttestationError(
                f"TEE type mismatch: expected {envelope['tee_type']}, "
                f"got {result.tee_type.value}",
                code="TEE_MISMATCH",
            )

        for name, expected in envelope["measurements"].items():
            actual = result.measurements.get(name)
            if actual != expected:
                raise AttestationError(
                    f"Measurement mismatch for {name}",
                    code="MEASUREMENT_MISMATCH",
                )

        key = await self.get_key(attestation_evidence, "encryption")

        temp_shield = Shield.__new__(Shield)
        temp_shield._key = key
        temp_shield._service = self.shield._service

        encrypted = base64.b64decode(envelope["encrypted"])
        return temp_shield.decrypt(encrypted)
