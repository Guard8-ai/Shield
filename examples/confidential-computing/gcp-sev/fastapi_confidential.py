"""
GCP Confidential VM FastAPI Example

This example shows how to run a Shield-protected FastAPI application
on a GCP Confidential VM with AMD SEV-SNP attestation.

Deployment:
    gcloud compute instances create shield-api \
        --machine-type n2d-standard-2 \
        --zone us-central1-a \
        --confidential-compute-type SEV_SNP \
        --image-family cos-stable \
        --image-project cos-cloud

Requirements:
    - GCP project with Confidential Computing enabled
    - n2d-* machine type with SEV_SNP
    - google-cloud-secret-manager for key retrieval
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
    SEVAttestationProvider,
    AttestationMiddleware,
    AttestationRouter,
    TEEKeyManager,
    requires_attestation,
    TEEType,
)
from shield.integrations.confidential.gcp_sev import (
    ConfidentialSpaceProvider,
    GCPSecretManager,
)

# Initialize FastAPI app
app = FastAPI(
    title="Shield GCP Confidential VM API",
    description="Secure API running on GCP Confidential VM with SEV-SNP",
)

# Configuration
GCP_PROJECT_ID = "your-project-id"
SECRET_MANAGER_SECRET = "shield-encryption-key"

# Initialize attestation provider
provider = SEVAttestationProvider(
    project_id=GCP_PROJECT_ID,
    expected_measurements={
        # Add expected measurements for your workload
        # "SEV_MEASUREMENT": "your_expected_measurement",
    },
    allowed_zones=["us-central1-a", "us-central1-b"],
)

# Initialize Secret Manager for key retrieval
secret_manager = GCPSecretManager(
    project_id=GCP_PROJECT_ID,
    provider=provider,
)

# Initialize key manager
key_manager = TEEKeyManager(
    password="bootstrap-password",  # Will be replaced with secret from Secret Manager
    service="gcp-confidential-api",
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
    """Initialize with secrets from Secret Manager after attestation."""
    try:
        # Generate our attestation to prove we're in a Confidential VM
        attestation = await provider.generate_evidence()

        # Retrieve encryption key from Secret Manager
        secret = await secret_manager.get_secret(
            SECRET_MANAGER_SECRET,
            attestation,
        )

        # Update key manager with real key
        from shield import Shield
        real_shield = Shield(secret.decode(), "gcp-confidential-api")
        key_manager.shield = real_shield

        print("Successfully retrieved encryption key from Secret Manager")
    except Exception as e:
        print(f"Warning: Could not retrieve secret: {e}")
        print("Running with bootstrap password")


@app.get("/health")
async def health():
    """Health check with TEE status."""
    is_confidential = await provider.is_confidential_vm()
    return {
        "status": "healthy",
        "environment": "gcp-confidential-vm",
        "sev_snp_enabled": is_confidential,
    }


@app.get("/metadata")
async def get_metadata():
    """Get VM metadata (no attestation required)."""
    try:
        metadata = await provider.get_instance_metadata()
        return {
            "instance": metadata,
            "confidential_vm": metadata.get("confidential_vm", False),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/secure/data")
async def get_secure_data(request: Request):
    """
    Get secure data (requires attestation).

    Client must provide attestation token proving they're also
    running in a Confidential VM.
    """
    attestation = getattr(request.state, "attestation", None)

    if attestation:
        return {
            "message": "Data from GCP Confidential VM",
            "client_verified": attestation.verified,
            "client_project": attestation.claims.get("project_id"),
            "client_zone": attestation.claims.get("zone"),
            "sev_snp_enabled": attestation.claims.get("sev_snp_enabled"),
        }

    return {"message": "Secure data"}


@app.post("/secure/encrypt")
@requires_attestation(
    provider=provider,
    required_tee_types=[TEEType.SEV_SNP],
)
async def encrypt_data(request: Request):
    """Encrypt data in the Confidential VM."""
    body = await request.json()
    data = body.get("data", "").encode()

    attestation = request.state.attestation

    # Create encryption context with attestation binding
    context = {
        "client_project": attestation.claims.get("project_id"),
        "client_instance": attestation.claims.get("instance_id"),
        "timestamp": attestation.timestamp,
    }

    # Encrypt with context binding
    key = await key_manager.get_key(
        attestation.raw_evidence,
        key_id="encryption",
    )

    shield = Shield.__new__(Shield)
    shield._key = key
    shield._service = "gcp-confidential-api"

    encrypted = shield.encrypt(data)

    return {
        "encrypted": base64.b64encode(encrypted).decode(),
        "context": context,
    }


@app.post("/secure/process")
@requires_attestation(
    provider=provider,
    required_tee_types=[TEEType.SEV_SNP],
)
async def process_sensitive_data(request: Request):
    """
    Process sensitive data entirely within the Confidential VM.

    The data is decrypted, processed, and re-encrypted without
    ever leaving the encrypted memory space.
    """
    body = await request.json()
    encrypted_input = base64.b64decode(body.get("encrypted_data", ""))
    operation = body.get("operation", "identity")

    attestation = request.state.attestation
    key = await key_manager.get_key(
        attestation.raw_evidence,
        key_id="processing",
    )

    shield = Shield.__new__(Shield)
    shield._key = key
    shield._service = "gcp-confidential-api"

    try:
        # Decrypt input
        decrypted = shield.decrypt(encrypted_input)

        # Process (example operations)
        if operation == "uppercase":
            result = decrypted.upper()
        elif operation == "hash":
            import hashlib
            result = hashlib.sha256(decrypted).hexdigest().encode()
        elif operation == "length":
            result = str(len(decrypted)).encode()
        else:
            result = decrypted

        # Re-encrypt output
        encrypted_output = shield.encrypt(result)

        return {
            "encrypted_result": base64.b64encode(encrypted_output).decode(),
            "operation": operation,
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Processing failed: {e}")


# Confidential Space example for containerized workloads
class ConfidentialSpaceHandler:
    """
    Handler for GCP Confidential Space workloads.

    Confidential Space provides stronger attestation with
    workload identity tokens.
    """

    def __init__(self, project_id: str):
        self.provider = ConfidentialSpaceProvider(
            project_id=project_id,
        )

    async def get_workload_token(self, audience: str) -> bytes:
        """Get workload identity token for service-to-service auth."""
        return await self.provider.generate_workload_token(audience)

    async def verify_peer_workload(self, token: bytes) -> dict:
        """Verify token from another Confidential Space workload."""
        result = await self.provider.verify(token)
        return {
            "verified": result.verified,
            "workload": result.claims,
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
