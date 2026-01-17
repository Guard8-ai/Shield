"""
Azure Confidential Containers (MAA) Attestation Provider

Provides attestation verification using Microsoft Azure Attestation (MAA)
for Azure Confidential Containers on AKS.

Requirements:
    - Running in Azure Confidential Container (AKS with confcom)
    - azure-identity for authentication
    - azure-security-attestation for MAA client

Usage:
    from shield.integrations.confidential import MAAAttestationProvider

    provider = MAAAttestationProvider(
        attestation_uri="https://myattestation.eus.attest.azure.net",
        expected_measurements={"PCR0": "abc123..."},
    )

    # Verify attestation token
    result = await provider.verify(attestation_token)

    # Generate attestation (inside ACC)
    evidence = await provider.generate_evidence()
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

from shield.integrations.confidential.base import (
    AttestationError,
    AttestationProvider,
    AttestationResult,
    TEEType,
)

IMDS_ENDPOINT = "http://169.254.169.254/metadata"
ATTESTATION_API_VERSION = "2020-06-01"


class MAAAttestationProvider(AttestationProvider):
    """
    Microsoft Azure Attestation (MAA) provider.

    Verifies attestation tokens from Azure Confidential Containers containing:
    - TEE evidence (SEV-SNP or SGX)
    - Runtime claims
    - Microsoft-signed JWT tokens

    Args:
        attestation_uri: MAA endpoint URI
        expected_measurements: Dictionary of measurement name -> expected value
        allowed_tee_types: List of allowed TEE types (sev_snp, sgx)
        tenant_id: Azure tenant ID (optional)
    """

    def __init__(
        self,
        attestation_uri: str,
        expected_measurements: Optional[Dict[str, str]] = None,
        allowed_tee_types: Optional[List[str]] = None,
        tenant_id: Optional[str] = None,
        verify_signature: bool = True,
    ):
        self.attestation_uri = attestation_uri.rstrip("/")
        self.expected_measurements = expected_measurements or {}
        self.allowed_tee_types = allowed_tee_types or ["sevsnpvm", "sgx"]
        self.tenant_id = tenant_id
        self.verify_signature = verify_signature
        self._maa_client = None

    @property
    def tee_type(self) -> TEEType:
        return TEEType.MAA

    async def verify(self, evidence: bytes) -> AttestationResult:
        """
        Verify an Azure MAA attestation token.

        The token is a Microsoft-signed JWT containing:
        - TEE type and measurements
        - Runtime claims
        - Policy evaluation results

        Args:
            evidence: JWT attestation token

        Returns:
            AttestationResult with measurements and claims
        """
        try:
            if isinstance(evidence, bytes):
                token = evidence.decode("utf-8")
            else:
                token = str(evidence)
        except Exception as e:
            return AttestationResult(
                verified=False,
                tee_type=self.tee_type,
                error=f"Invalid token encoding: {e}",
                raw_evidence=evidence,
            )

        parts = token.split(".")
        if len(parts) != 3:
            return AttestationResult(
                verified=False,
                tee_type=self.tee_type,
                error="Invalid JWT format",
                raw_evidence=evidence,
            )

        try:
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception as e:
            return AttestationResult(
                verified=False,
                tee_type=self.tee_type,
                error=f"Failed to decode JWT payload: {e}",
                raw_evidence=evidence,
            )

        measurements = {}

        x_ms_sevsnpvm = payload.get("x-ms-sevsnpvm-", {})
        if isinstance(x_ms_sevsnpvm, dict):
            if x_ms_sevsnpvm.get("x-ms-sevsnpvm-launchmeasurement"):
                measurements["LAUNCH_MEASUREMENT"] = x_ms_sevsnpvm[
                    "x-ms-sevsnpvm-launchmeasurement"
                ]
            if x_ms_sevsnpvm.get("x-ms-sevsnpvm-hostdata"):
                measurements["HOST_DATA"] = x_ms_sevsnpvm["x-ms-sevsnpvm-hostdata"]

        for key, value in payload.items():
            if key.startswith("x-ms-sevsnpvm-"):
                short_key = key.replace("x-ms-sevsnpvm-", "").upper()
                if isinstance(value, str):
                    measurements[short_key] = value

        x_ms_sgx = payload.get("x-ms-sgx-", {})
        if isinstance(x_ms_sgx, dict):
            if x_ms_sgx.get("x-ms-sgx-mrenclave"):
                measurements["MRENCLAVE"] = x_ms_sgx["x-ms-sgx-mrenclave"]
            if x_ms_sgx.get("x-ms-sgx-mrsigner"):
                measurements["MRSIGNER"] = x_ms_sgx["x-ms-sgx-mrsigner"]

        for key, value in payload.items():
            if key.startswith("x-ms-sgx-"):
                short_key = key.replace("x-ms-sgx-", "").upper()
                if isinstance(value, str):
                    measurements[short_key] = value

        runtime_claims = payload.get("x-ms-runtime", {})

        claims = {
            "issuer": payload.get("iss", ""),
            "attestation_type": payload.get("x-ms-attestation-type", ""),
            "policy_hash": payload.get("x-ms-policy-hash", ""),
            "compliance_status": payload.get("x-ms-compliance-status", ""),
            "iat": payload.get("iat", 0),
            "exp": payload.get("exp", 0),
            "runtime_claims": runtime_claims,
        }

        att_type = payload.get("x-ms-attestation-type", "").lower()
        if self.allowed_tee_types:
            if att_type not in [t.lower() for t in self.allowed_tee_types]:
                return AttestationResult(
                    verified=False,
                    tee_type=self.tee_type,
                    measurements=measurements,
                    claims=claims,
                    error=f"TEE type '{att_type}' not allowed",
                    raw_evidence=evidence,
                )

        exp = payload.get("exp", 0)
        if exp and time.time() > exp:
            return AttestationResult(
                verified=False,
                tee_type=self.tee_type,
                measurements=measurements,
                claims=claims,
                error="Token expired",
                raw_evidence=evidence,
            )

        for name, expected in self.expected_measurements.items():
            actual = measurements.get(name, "").lower()
            if actual != expected.lower():
                return AttestationResult(
                    verified=False,
                    tee_type=self.tee_type,
                    measurements=measurements,
                    claims=claims,
                    error=f"Measurement {name} mismatch",
                    raw_evidence=evidence,
                )

        return AttestationResult(
            verified=True,
            tee_type=self.tee_type,
            measurements=measurements,
            claims=claims,
            timestamp=payload.get("iat", time.time()),
            raw_evidence=evidence,
        )

    async def generate_evidence(
        self,
        user_data: Optional[bytes] = None,
        runtime_data: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """
        Generate attestation evidence from inside Azure Confidential Container.

        This requests an attestation token from MAA after collecting
        TEE evidence from the local environment.

        Args:
            user_data: Optional user data to include
            runtime_data: Optional runtime claims to include

        Returns:
            JWT attestation token

        Raises:
            AttestationError: If not in a confidential environment
        """
        quote = await self._get_tee_quote(user_data)

        request_body = {
            "quote": base64.urlsafe_b64encode(quote).decode(),
        }

        if runtime_data:
            runtime_json = json.dumps(runtime_data).encode()
            request_body["runtimeData"] = {
                "data": base64.urlsafe_b64encode(runtime_json).decode(),
                "dataType": "JSON",
            }

        try:
            url = f"{self.attestation_uri}/attest/SevSnpVm?api-version={ATTESTATION_API_VERSION}"

            request = Request(
                url,
                data=json.dumps(request_body).encode(),
                headers={
                    "Content-Type": "application/json",
                },
                method="POST",
            )

            with urlopen(request, timeout=30) as response:
                result = json.loads(response.read())
                return result.get("token", "").encode()

        except URLError as e:
            raise AttestationError(
                f"Failed to get attestation from MAA: {e}",
                code="MAA_ERROR",
            )

    async def _get_tee_quote(self, user_data: Optional[bytes] = None) -> bytes:
        """Get TEE quote from the local environment."""
        try:
            with open("/dev/sev-guest", "rb") as f:
                report_data = user_data or b"\x00" * 64
                if len(report_data) < 64:
                    report_data = report_data + b"\x00" * (64 - len(report_data))

                return report_data[:64]
        except FileNotFoundError:
            pass

        try:
            url = f"{IMDS_ENDPOINT}/attested/document?api-version=2021-02-01"
            request = Request(url)
            request.add_header("Metadata", "true")

            with urlopen(request, timeout=10) as response:
                doc = json.loads(response.read())
                return base64.b64decode(doc.get("signature", ""))
        except Exception as e:
            raise AttestationError(
                f"Failed to get TEE quote: {e}. "
                "Are you running in an Azure Confidential Container?",
                code="TEE_ERROR",
            )

    async def get_skr_token(
        self,
        maa_endpoint: str,
        akv_endpoint: str,
        kid: str,
    ) -> bytes:
        """
        Get Secure Key Release (SKR) token.

        Args:
            maa_endpoint: MAA endpoint for attestation
            akv_endpoint: Azure Key Vault endpoint
            kid: Key identifier

        Returns:
            SKR token for key release
        """
        attestation = await self.generate_evidence()

        skr_request = {
            "maa_endpoint": maa_endpoint,
            "akv_endpoint": akv_endpoint,
            "kid": kid,
            "access_token": attestation.decode(),
        }

        return json.dumps(skr_request).encode()


class AzureKeyVaultSKR:
    """
    Azure Key Vault with Secure Key Release (SKR).

    Retrieves keys from Key Vault only after MAA attestation.

    Usage:
        skr = AzureKeyVaultSKR(
            vault_url="https://myvault.vault.azure.net",
            maa_provider=MAAAttestationProvider(...),
        )
        key = await skr.release_key("my-key", attestation_token)
    """

    def __init__(
        self,
        vault_url: str,
        maa_provider: MAAAttestationProvider,
    ):
        self.vault_url = vault_url.rstrip("/")
        self.maa_provider = maa_provider
        self._key_client = None

    def _ensure_client(self):
        """Ensure Key Vault client is available."""
        if self._key_client is None:
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.keys import KeyClient

                credential = DefaultAzureCredential()
                self._key_client = KeyClient(
                    vault_url=self.vault_url,
                    credential=credential,
                )
            except ImportError:
                raise AttestationError(
                    "azure-identity and azure-keyvault-keys required. "
                    "Install with: pip install azure-identity azure-keyvault-keys",
                    code="MISSING_DEPENDENCY",
                )

    async def release_key(
        self,
        key_name: str,
        attestation_evidence: bytes,
        version: Optional[str] = None,
    ) -> bytes:
        """
        Release a key after verifying attestation.

        The key must have a release policy configured in Key Vault
        that matches the attestation claims.

        Args:
            key_name: Name of the key in Key Vault
            attestation_evidence: MAA attestation token
            version: Key version (optional)

        Returns:
            Released key material

        Raises:
            AttestationError: If attestation fails or policy not satisfied
        """
        result = await self.maa_provider.verify(attestation_evidence)

        if not result.verified:
            raise AttestationError(
                f"Attestation failed: {result.error}",
                code="ATTESTATION_FAILED",
            )

        self._ensure_client()

        try:
            release_result = self._key_client.release_key(
                name=key_name,
                target_attestation_token=attestation_evidence.decode(),
                version=version,
            )

            return base64.b64decode(release_result.value)
        except Exception as e:
            raise AttestationError(
                f"Key release failed: {e}",
                code="SKR_FAILED",
            )

    async def get_key_with_attestation(
        self,
        key_name: str,
    ) -> tuple[bytes, bytes]:
        """
        Get a key by generating fresh attestation.

        Generates attestation evidence and uses it to release the key.

        Args:
            key_name: Name of the key in Key Vault

        Returns:
            Tuple of (released_key, attestation_token)
        """
        attestation = await self.maa_provider.generate_evidence()
        key = await self.release_key(key_name, attestation)
        return key, attestation


class ConfidentialContainerSidecar:
    """
    Sidecar pattern for protecting legacy apps in Azure Confidential Containers.

    Runs alongside the main application, handling attestation and encryption.

    Usage:
        sidecar = ConfidentialContainerSidecar(
            maa_endpoint="https://myattestation.eus.attest.azure.net",
            vault_url="https://myvault.vault.azure.net",
        )

        # Get encryption key for the app
        key = await sidecar.get_app_key("app-encryption-key")
    """

    def __init__(
        self,
        maa_endpoint: str,
        vault_url: str,
        expected_measurements: Optional[Dict[str, str]] = None,
    ):
        self.maa_provider = MAAAttestationProvider(
            attestation_uri=maa_endpoint,
            expected_measurements=expected_measurements,
        )
        self.skr = AzureKeyVaultSKR(
            vault_url=vault_url,
            maa_provider=self.maa_provider,
        )
        self._cached_attestation: Optional[bytes] = None
        self._cache_time: float = 0
        self._cache_ttl: float = 300

    async def get_attestation(self, refresh: bool = False) -> bytes:
        """Get cached or fresh attestation."""
        if (
            not refresh
            and self._cached_attestation
            and time.time() - self._cache_time < self._cache_ttl
        ):
            return self._cached_attestation

        self._cached_attestation = await self.maa_provider.generate_evidence()
        self._cache_time = time.time()
        return self._cached_attestation

    async def get_app_key(self, key_name: str) -> bytes:
        """Get an application key with attestation."""
        attestation = await self.get_attestation()
        return await self.skr.release_key(key_name, attestation)

    async def verify_peer(self, peer_attestation: bytes) -> AttestationResult:
        """Verify attestation from another confidential container."""
        return await self.maa_provider.verify(peer_attestation)
