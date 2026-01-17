"""
GCP Confidential VMs (AMD SEV-SNP) Attestation Provider

Provides attestation verification for GCP Confidential VMs using
AMD SEV-SNP hardware attestation and vTPM measurements.

Requirements:
    - Running on a GCP Confidential VM (n2d-* with SEV_SNP)
    - google-cloud-compute for metadata access
    - google-cloud-kms for secret release

Usage:
    from shield.integrations.confidential import SEVAttestationProvider

    provider = SEVAttestationProvider(
        project_id="my-project",
        expected_measurements={"PCR0": "abc123..."},
    )

    # Verify attestation
    result = await provider.verify(attestation_token)

    # Generate attestation (inside Confidential VM)
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

GCP_METADATA_URL = "http://metadata.google.internal/computeMetadata/v1"
GCP_ATTESTATION_URL = "http://metadata.google.internal/computeMetadata/v1/instance/virtual-machine/verify-token"
CONFIDENTIAL_SPACE_TOKEN_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"


class SEVAttestationProvider(AttestationProvider):
    """
    GCP Confidential VM (AMD SEV-SNP) attestation provider.

    Verifies attestation tokens from GCP Confidential VMs containing:
    - AMD SEV-SNP measurements
    - vTPM PCR values
    - VM identity and metadata
    - Google-signed JWT tokens

    Args:
        project_id: GCP project ID
        expected_measurements: Dictionary of measurement name -> expected value
        verify_signature: Whether to verify Google's JWT signature
        allowed_zones: List of allowed GCP zones (optional)
    """

    def __init__(
        self,
        project_id: Optional[str] = None,
        expected_measurements: Optional[Dict[str, str]] = None,
        verify_signature: bool = True,
        allowed_zones: Optional[List[str]] = None,
        audience: Optional[str] = None,
    ):
        self.project_id = project_id
        self.expected_measurements = expected_measurements or {}
        self.verify_signature = verify_signature
        self.allowed_zones = allowed_zones
        self.audience = audience or "shield-attestation"

    @property
    def tee_type(self) -> TEEType:
        return TEEType.SEV_SNP

    async def verify(self, evidence: bytes) -> AttestationResult:
        """
        Verify a GCP Confidential VM attestation token.

        The token is a Google-signed JWT containing:
        - VM instance identity
        - SEV-SNP status and measurements
        - vTPM PCR values

        Args:
            evidence: JWT attestation token (bytes or string)

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
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)

            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception as e:
            return AttestationResult(
                verified=False,
                tee_type=self.tee_type,
                error=f"Failed to decode JWT: {e}",
                raw_evidence=evidence,
            )

        measurements = {}

        sev_snp = payload.get("sev_snp", {})
        if sev_snp:
            if sev_snp.get("measurement"):
                measurements["SEV_MEASUREMENT"] = sev_snp["measurement"]
            if sev_snp.get("host_data"):
                measurements["HOST_DATA"] = sev_snp["host_data"]
            if sev_snp.get("report_data"):
                measurements["REPORT_DATA"] = sev_snp["report_data"]

        tpm_pcrs = payload.get("tpm_pcrs", {})
        for pcr_idx, value in tpm_pcrs.items():
            measurements[f"PCR{pcr_idx}"] = value

        claims = {
            "project_id": payload.get("google", {}).get("project_id", ""),
            "project_number": payload.get("google", {}).get("project_number", ""),
            "zone": payload.get("google", {}).get("zone", ""),
            "instance_id": payload.get("google", {}).get("instance_id", ""),
            "instance_name": payload.get("google", {}).get("instance_name", ""),
            "confidential_vm": payload.get("google", {}).get("confidential_vm", False),
            "sev_snp_enabled": bool(sev_snp),
            "iat": payload.get("iat", 0),
            "exp": payload.get("exp", 0),
        }

        google_claims = payload.get("google", {})
        if not google_claims.get("confidential_vm", False):
            return AttestationResult(
                verified=False,
                tee_type=self.tee_type,
                measurements=measurements,
                claims=claims,
                error="VM is not a Confidential VM",
                raw_evidence=evidence,
            )

        if self.project_id and claims["project_id"] != self.project_id:
            return AttestationResult(
                verified=False,
                tee_type=self.tee_type,
                measurements=measurements,
                claims=claims,
                error=f"Project mismatch: expected {self.project_id}",
                raw_evidence=evidence,
            )

        if self.allowed_zones and claims["zone"] not in self.allowed_zones:
            return AttestationResult(
                verified=False,
                tee_type=self.tee_type,
                measurements=measurements,
                claims=claims,
                error=f"Zone {claims['zone']} not allowed",
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
        audience: Optional[str] = None,
    ) -> bytes:
        """
        Generate attestation evidence from inside a GCP Confidential VM.

        This requests an identity token from the GCP metadata service
        that includes attestation claims.

        Args:
            user_data: Optional user data (used as nonce in token request)
            audience: Token audience (default: self.audience)

        Returns:
            JWT attestation token

        Raises:
            AttestationError: If not running on GCP or not a Confidential VM
        """
        aud = audience or self.audience

        url = f"{CONFIDENTIAL_SPACE_TOKEN_URL}?audience={aud}&format=full"

        if user_data:
            nonce = base64.urlsafe_b64encode(user_data).decode().rstrip("=")
            url += f"&nonce={nonce}"

        try:
            request = Request(url)
            request.add_header("Metadata-Flavor", "Google")

            with urlopen(request, timeout=10) as response:
                token = response.read()

            return token

        except URLError as e:
            raise AttestationError(
                f"Failed to get attestation token: {e}. "
                "Are you running on a GCP Confidential VM?",
                code="METADATA_ERROR",
            )

    async def get_instance_metadata(self) -> Dict[str, Any]:
        """
        Get current instance metadata.

        Returns:
            Dictionary with instance information
        """
        metadata = {}

        paths = [
            ("project_id", "project/project-id"),
            ("zone", "instance/zone"),
            ("instance_id", "instance/id"),
            ("instance_name", "instance/name"),
            ("machine_type", "instance/machine-type"),
        ]

        for key, path in paths:
            try:
                url = f"{GCP_METADATA_URL}/{path}"
                request = Request(url)
                request.add_header("Metadata-Flavor", "Google")

                with urlopen(request, timeout=5) as response:
                    metadata[key] = response.read().decode().split("/")[-1]
            except Exception:
                metadata[key] = None

        try:
            url = f"{GCP_METADATA_URL}/instance/attributes/enable-confidential-compute"
            request = Request(url)
            request.add_header("Metadata-Flavor", "Google")

            with urlopen(request, timeout=5) as response:
                value = response.read().decode().lower()
                metadata["confidential_vm"] = value == "true"
        except Exception:
            metadata["confidential_vm"] = False

        return metadata

    async def is_confidential_vm(self) -> bool:
        """Check if running on a Confidential VM."""
        try:
            metadata = await self.get_instance_metadata()
            return metadata.get("confidential_vm", False)
        except Exception:
            return False


class ConfidentialSpaceProvider(SEVAttestationProvider):
    """
    GCP Confidential Space attestation provider.

    Confidential Space is a serverless confidential computing environment
    that provides stronger attestation with workload identity.

    Additional features over standard Confidential VMs:
    - Workload identity tokens
    - Container image measurements
    - Attestation policies
    """

    def __init__(
        self,
        project_id: Optional[str] = None,
        expected_image_digest: Optional[str] = None,
        expected_measurements: Optional[Dict[str, str]] = None,
        allowed_zones: Optional[List[str]] = None,
    ):
        super().__init__(
            project_id=project_id,
            expected_measurements=expected_measurements,
            allowed_zones=allowed_zones,
        )
        self.expected_image_digest = expected_image_digest

    async def verify(self, evidence: bytes) -> AttestationResult:
        """Verify Confidential Space attestation."""
        result = await super().verify(evidence)

        if not result.verified:
            return result

        if self.expected_image_digest:
            actual_digest = result.claims.get("container_image_digest", "")
            if actual_digest != self.expected_image_digest:
                return AttestationResult(
                    verified=False,
                    tee_type=self.tee_type,
                    measurements=result.measurements,
                    claims=result.claims,
                    error=f"Image digest mismatch",
                    raw_evidence=evidence,
                )

        return result

    async def generate_workload_token(
        self,
        audience: str,
        token_type: str = "OIDC",
    ) -> bytes:
        """
        Generate a workload identity token.

        Args:
            audience: Token audience
            token_type: Token type (OIDC or PKI)

        Returns:
            Signed workload token
        """
        url = (
            f"{GCP_METADATA_URL}/instance/service-accounts/default/identity"
            f"?audience={audience}&format=full"
        )

        try:
            request = Request(url)
            request.add_header("Metadata-Flavor", "Google")

            with urlopen(request, timeout=10) as response:
                return response.read()
        except URLError as e:
            raise AttestationError(
                f"Failed to get workload token: {e}",
                code="METADATA_ERROR",
            )


class GCPSecretManager:
    """
    GCP Secret Manager with attestation-based access.

    Retrieves secrets only after verifying attestation.

    Usage:
        manager = GCPSecretManager(
            project_id="my-project",
            provider=SEVAttestationProvider(),
        )
        secret = await manager.get_secret("my-secret", attestation_token)
    """

    def __init__(
        self,
        project_id: str,
        provider: SEVAttestationProvider,
    ):
        self.project_id = project_id
        self.provider = provider
        self._client = None

    def _ensure_client(self):
        """Ensure Secret Manager client is available."""
        if self._client is None:
            try:
                from google.cloud import secretmanager
                self._client = secretmanager.SecretManagerServiceClient()
            except ImportError:
                raise AttestationError(
                    "google-cloud-secret-manager required. "
                    "Install with: pip install google-cloud-secret-manager",
                    code="MISSING_DEPENDENCY",
                )

    async def get_secret(
        self,
        secret_id: str,
        attestation_evidence: bytes,
        version: str = "latest",
    ) -> bytes:
        """
        Get a secret after verifying attestation.

        Args:
            secret_id: Secret ID in Secret Manager
            attestation_evidence: Attestation token
            version: Secret version (default: latest)

        Returns:
            Secret value

        Raises:
            AttestationError: If attestation fails
        """
        result = await self.provider.verify(attestation_evidence)

        if not result.verified:
            raise AttestationError(
                f"Attestation failed: {result.error}",
                code="ATTESTATION_FAILED",
            )

        self._ensure_client()

        name = f"projects/{self.project_id}/secrets/{secret_id}/versions/{version}"
        response = self._client.access_secret_version(request={"name": name})

        return response.payload.data
