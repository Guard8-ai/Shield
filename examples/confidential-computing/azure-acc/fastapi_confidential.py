"""
Azure Confidential Container FastAPI Example

This example shows how to run a Shield-protected FastAPI application
in an Azure Confidential Container on AKS with MAA attestation.

Deployment:
    1. Create AKS cluster with confcom add-on
    2. Deploy using Helm chart with confidential node pool
    3. Configure MAA and Key Vault for attestation

Requirements:
    - AKS cluster with confcom add-on enabled
    - DC*as_v5 or DC*s_v3 node pool
    - Azure MAA endpoint configured
    - Azure Key Vault with SKR-enabled keys
"""

import asyncio
import base64
import json
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from shield import Shield
from shield.integrations import ShieldMiddleware
from shield.integrations.confidential import (
    MAAAttestationProvider,
    AttestationMiddleware,
    AttestationRouter,
    TEEKeyManager,
    requires_attestation,
    TEEType,
)
from shield.integrations.confidential.azure_maa import (
    AzureKeyVaultSKR,
    ConfidentialContainerSidecar,
)

# Initialize FastAPI app
app = FastAPI(
    title="Shield Azure Confidential Container API",
    description="Secure API running in Azure Confidential Container",
)

# Configuration
MAA_ENDPOINT = "https://sharedeus.eus.attest.azure.net"  # Or your custom MAA
KEY_VAULT_URL = "https://your-vault.vault.azure.net"
ENCRYPTION_KEY_NAME = "shield-encryption-key"

# Initialize MAA attestation provider
provider = MAAAttestationProvider(
    attestation_uri=MAA_ENDPOINT,
    expected_measurements={
        # Add expected SEV-SNP or SGX measurements
        # "LAUNCH_MEASUREMENT": "your_expected_measurement",
    },
    allowed_tee_types=["sevsnpvm", "sgx"],
)

# Initialize Key Vault SKR for secure key release
skr = AzureKeyVaultSKR(
    vault_url=KEY_VAULT_URL,
    maa_provider=provider,
)

# Initialize key manager
key_manager = TEEKeyManager(
    password="bootstrap-password",
    service="azure-confidential-api",
    provider=provider,
)

# Add attestation middleware
app.add_middleware(
    AttestationMiddleware,
    provider=provider,
    require_client_attestation=True,
    provide_server_attestation=True,
    exclude_routes=["/health", "/docs", "/openapi.json", "/attestation"],
)

# Include attestation router
attestation_router = AttestationRouter(provider=provider)
app.include_router(attestation_router.router, prefix="/api")


@app.on_event("startup")
async def startup():
    """Initialize encryption key via Secure Key Release."""
    try:
        # Get encryption key from Key Vault using SKR
        key, attestation = await skr.get_key_with_attestation(ENCRYPTION_KEY_NAME)

        # Update Shield with real key
        from shield import Shield
        import hashlib
        derived_key = hashlib.sha256(key).digest()

        real_shield = Shield.__new__(Shield)
        real_shield._key = derived_key
        real_shield._service = "azure-confidential-api"
        key_manager.shield = real_shield

        print("Successfully retrieved encryption key via SKR")
    except Exception as e:
        print(f"Warning: Could not retrieve key via SKR: {e}")
        print("Running with bootstrap password")


@app.get("/health")
async def health():
    """Health check with TEE status."""
    try:
        attestation = await provider.generate_evidence()
        result = await provider.verify(attestation)

        return {
            "status": "healthy",
            "environment": "azure-confidential-container",
            "in_tee": result.verified,
            "tee_type": result.claims.get("attestation_type"),
        }
    except Exception:
        return {
            "status": "degraded",
            "environment": "azure-confidential-container",
            "in_tee": False,
        }


@app.get("/secure/data")
async def get_secure_data(request: Request):
    """
    Get secure data (requires attestation).

    Client must provide MAA attestation token.
    """
    attestation = getattr(request.state, "attestation", None)

    if attestation:
        return {
            "message": "Data from Azure Confidential Container",
            "client_verified": attestation.verified,
            "client_tee_type": attestation.claims.get("attestation_type"),
            "compliance_status": attestation.claims.get("compliance_status"),
        }

    return {"message": "Secure data"}


@app.post("/secure/encrypt")
@requires_attestation(
    provider=provider,
    required_tee_types=[TEEType.MAA],
)
async def encrypt_data(request: Request):
    """Encrypt data in the Confidential Container."""
    body = await request.json()
    data = body.get("data", "").encode()

    attestation = request.state.attestation
    key = await key_manager.get_key(
        attestation.raw_evidence,
        key_id="encryption",
    )

    shield = Shield.__new__(Shield)
    shield._key = key
    shield._service = "azure-confidential-api"

    encrypted = shield.encrypt(data)

    return {
        "encrypted": base64.b64encode(encrypted).decode(),
    }


@app.post("/secure/release-key")
@requires_attestation(
    provider=provider,
    required_tee_types=[TEEType.MAA],
)
async def release_key(request: Request):
    """
    Release a key from Key Vault via SKR.

    The key is only released if the attestation satisfies
    the Key Vault release policy.
    """
    body = await request.json()
    key_name = body.get("key_name")

    if not key_name:
        raise HTTPException(status_code=400, detail="key_name required")

    attestation = request.state.attestation

    try:
        key = await skr.release_key(key_name, attestation.raw_evidence)

        # Don't return raw key - return confirmation
        return {
            "success": True,
            "key_name": key_name,
            "key_length": len(key),
        }
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"Key release failed: {e}")


@app.post("/secure/database-query")
@requires_attestation(
    provider=provider,
    required_tee_types=[TEEType.MAA],
)
async def secure_database_query(request: Request):
    """
    Execute encrypted database query.

    Query is decrypted inside TEE, executed, and results
    are encrypted before returning.
    """
    body = await request.json()
    encrypted_query = base64.b64decode(body.get("encrypted_query", ""))

    attestation = request.state.attestation
    key = await key_manager.get_key(
        attestation.raw_evidence,
        key_id="database",
    )

    shield = Shield.__new__(Shield)
    shield._key = key
    shield._service = "azure-confidential-api"

    try:
        # Decrypt query
        query = shield.decrypt(encrypted_query).decode()

        # Execute query (mock - replace with real database)
        results = [
            {"id": 1, "name": "Confidential Record 1"},
            {"id": 2, "name": "Confidential Record 2"},
        ]

        # Encrypt results
        results_json = json.dumps(results).encode()
        encrypted_results = shield.encrypt(results_json)

        return {
            "encrypted_results": base64.b64encode(encrypted_results).decode(),
            "row_count": len(results),
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Query failed: {e}")


# Sidecar pattern for legacy app protection
class LegacyAppSidecar:
    """
    Sidecar for protecting legacy applications.

    Intercepts traffic to legacy app and handles encryption/attestation.
    """

    def __init__(
        self,
        legacy_app_url: str,
        maa_endpoint: str,
        vault_url: str,
    ):
        self.legacy_app_url = legacy_app_url
        self.sidecar = ConfidentialContainerSidecar(
            maa_endpoint=maa_endpoint,
            vault_url=vault_url,
        )
        self.shield = None

    async def initialize(self, key_name: str):
        """Initialize with key from Key Vault."""
        key = await self.sidecar.get_app_key(key_name)
        self.shield = Shield.__new__(Shield)
        self.shield._key = key[:32]
        self.shield._service = "legacy-app-sidecar"

    async def forward_request(
        self,
        method: str,
        path: str,
        encrypted_body: bytes = None,
    ) -> bytes:
        """Forward decrypted request to legacy app, encrypt response."""
        from urllib.request import Request, urlopen

        # Decrypt incoming body
        body = None
        if encrypted_body and self.shield:
            body = self.shield.decrypt(encrypted_body)

        # Forward to legacy app
        url = f"{self.legacy_app_url}{path}"
        request = Request(url, data=body, method=method)

        with urlopen(request, timeout=30) as response:
            response_body = response.read()

        # Encrypt response
        if self.shield:
            return self.shield.encrypt(response_body)
        return response_body


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
