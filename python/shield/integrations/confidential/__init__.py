"""
Confidential Computing Integrations for Shield

Provides attestation verification and TEE-aware key management for:
- AWS Nitro Enclaves
- GCP Confidential VMs (AMD SEV-SNP)
- Azure Confidential Containers (MAA)
- Intel SGX (Gramine/Occlum)

Usage:
    from shield.integrations.confidential import (
        AttestationProvider,
        TEEKeyManager,
        AttestationMiddleware,
        requires_attestation,
    )

    # Verify attestation
    provider = NitroAttestationProvider()
    result = await provider.verify(attestation_doc)

    # TEE-aware key management
    key_manager = TEEKeyManager(
        password="secret",
        service="api.example.com",
        provider=provider,
    )
    key = await key_manager.get_key(attestation_doc)
"""

from shield.integrations.confidential.base import (
    AttestationProvider,
    AttestationResult,
    AttestationError,
    TEEType,
    TEEKeyManager,
)
from shield.integrations.confidential.aws_nitro import NitroAttestationProvider
from shield.integrations.confidential.gcp_sev import SEVAttestationProvider
from shield.integrations.confidential.azure_maa import MAAAttestationProvider
from shield.integrations.confidential.intel_sgx import SGXAttestationProvider
from shield.integrations.confidential.middleware import (
    AttestationMiddleware,
    requires_attestation,
)

__all__ = [
    # Base types
    "AttestationProvider",
    "AttestationResult",
    "AttestationError",
    "TEEType",
    "TEEKeyManager",
    # Providers
    "NitroAttestationProvider",
    "SEVAttestationProvider",
    "MAAAttestationProvider",
    "SGXAttestationProvider",
    # Middleware
    "AttestationMiddleware",
    "requires_attestation",
]
