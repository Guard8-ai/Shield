"""
Confidential Computing Integrations for Shield

Provides attestation evidence parsing and TEE-aware key management for:
- AWS Nitro Enclaves
- GCP Confidential VMs (AMD SEV-SNP)
- Azure Confidential Containers (MAA)
- Intel SGX (Gramine/Occlum)

.. warning::
    **These Python providers are FAIL-CLOSED and do NOT cryptographically verify
    attestation.** They parse evidence and compare measurement fields, but they
    do **not** verify the quote/token signature or certificate chain. By default
    ``verify()`` therefore returns ``verified=False`` (so forged evidence cannot
    release keys via ``TEEKeyManager``). The production-grade, signature-and-cert
    -chain-verifying implementation is the **Rust ``shield-core`` confidential
    module**. Pass ``allow_insecure_demo=True`` to a provider only to accept
    unverified evidence in a non-production test/demo (it warns loudly).

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
