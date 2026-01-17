"""
Intel SGX Enclave FastAPI Example (with Gramine)

This example shows how to run a Shield-protected FastAPI application
inside an Intel SGX enclave using Gramine LibOS.

Deployment:
    1. Generate Gramine manifest: gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu shield.manifest.template > shield.manifest
    2. Sign manifest: gramine-sgx-sign --manifest shield.manifest --output shield.manifest.sgx
    3. Run: gramine-sgx ./shield

Requirements:
    - Intel CPU with SGX support
    - SGX driver (in-kernel since Linux 5.11)
    - Gramine installed
    - DCAP libraries for attestation
"""

import asyncio
import base64
import json
import os
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from shield import Shield
from shield.integrations import ShieldMiddleware
from shield.integrations.confidential import (
    SGXAttestationProvider,
    AttestationMiddleware,
    AttestationRouter,
    TEEKeyManager,
    requires_attestation,
    TEEType,
)
from shield.integrations.confidential.intel_sgx import (
    SealedStorage,
    GramineManifestHelper,
)

# Initialize FastAPI app
app = FastAPI(
    title="Shield SGX Enclave API",
    description="Secure API running inside Intel SGX enclave via Gramine",
)

# Configuration
# Get these values from: gramine-sgx-sigstruct-view shield.sig
EXPECTED_MRENCLAVE = os.environ.get("EXPECTED_MRENCLAVE")
EXPECTED_MRSIGNER = os.environ.get("EXPECTED_MRSIGNER")

# Initialize attestation provider
provider = SGXAttestationProvider(
    expected_mrenclave=EXPECTED_MRENCLAVE,
    expected_mrsigner=EXPECTED_MRSIGNER,
    min_isv_svn=1,
    verify_with_pccs=False,  # Set True in production
)

# Initialize sealed storage for persistent secrets
sealed_storage = SealedStorage(
    seal_to="mrenclave",  # Seal to this specific enclave
    storage_path="/data/sealed",
)

# Initialize key manager
key_manager = TEEKeyManager(
    password="bootstrap-password",
    service="sgx-enclave-api",
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
    """Initialize enclave with sealed secrets."""
    try:
        # Try to load sealed encryption key
        key = await sealed_storage.load("encryption_key")
        print("Loaded sealed encryption key")

        real_shield = Shield.__new__(Shield)
        real_shield._key = key[:32]
        real_shield._service = "sgx-enclave-api"
        key_manager.shield = real_shield

    except Exception:
        print("No sealed key found, generating new one")
        # Generate and seal new key
        import secrets
        new_key = secrets.token_bytes(32)

        await sealed_storage.store("encryption_key", new_key)
        print("Generated and sealed new encryption key")

        real_shield = Shield.__new__(Shield)
        real_shield._key = new_key
        real_shield._service = "sgx-enclave-api"
        key_manager.shield = real_shield


@app.get("/health")
async def health():
    """Health check with enclave status."""
    in_enclave = os.path.exists("/dev/attestation/quote")
    return {
        "status": "healthy",
        "environment": "sgx-enclave" if in_enclave else "native",
        "sgx_enabled": in_enclave,
    }


@app.get("/enclave/info")
async def enclave_info():
    """Get enclave information and measurements."""
    try:
        # Generate self-attestation
        attestation = await provider.generate_evidence()
        result = await provider.verify(attestation)

        return {
            "in_enclave": True,
            "mrenclave": result.measurements.get("MRENCLAVE"),
            "mrsigner": result.measurements.get("MRSIGNER"),
            "isv_prod_id": result.claims.get("isv_prod_id"),
            "isv_svn": result.claims.get("isv_svn"),
        }
    except Exception as e:
        return {
            "in_enclave": False,
            "error": str(e),
        }


@app.get("/secure/data")
async def get_secure_data(request: Request):
    """
    Get secure data (requires attestation).

    Client must provide SGX quote proving they're in an enclave.
    """
    attestation = getattr(request.state, "attestation", None)

    if attestation:
        return {
            "message": "Data from Intel SGX enclave",
            "client_verified": attestation.verified,
            "client_mrenclave": attestation.measurements.get("MRENCLAVE"),
            "client_mrsigner": attestation.measurements.get("MRSIGNER"),
        }

    return {"message": "Secure data"}


@app.post("/secure/encrypt")
@requires_attestation(
    provider=provider,
    required_tee_types=[TEEType.SGX],
)
async def encrypt_data(request: Request):
    """Encrypt data inside the SGX enclave."""
    body = await request.json()
    data = body.get("data", "").encode()

    attestation = request.state.attestation
    key = await key_manager.get_key(
        attestation.raw_evidence,
        key_id="encryption",
    )

    shield = Shield.__new__(Shield)
    shield._key = key
    shield._service = "sgx-enclave-api"

    encrypted = shield.encrypt(data)

    return {
        "encrypted": base64.b64encode(encrypted).decode(),
    }


@app.post("/secure/seal")
@requires_attestation(
    provider=provider,
    required_tee_types=[TEEType.SGX],
)
async def seal_data(request: Request):
    """
    Seal data to enclave identity.

    Data can only be unsealed by this exact enclave (MRENCLAVE match).
    """
    body = await request.json()
    data = body.get("data", "").encode()
    key = body.get("key", "user_data")

    try:
        await sealed_storage.store(key, data)
        return {
            "success": True,
            "key": key,
            "sealed_to": "mrenclave",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sealing failed: {e}")


@app.post("/secure/unseal")
@requires_attestation(
    provider=provider,
    required_tee_types=[TEEType.SGX],
)
async def unseal_data(request: Request):
    """Unseal previously sealed data."""
    body = await request.json()
    key = body.get("key", "user_data")

    try:
        data = await sealed_storage.load(key)
        return {
            "success": True,
            "data": data.decode(),
        }
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Unsealing failed: {e}")


@app.post("/secure/key-management")
@requires_attestation(
    provider=provider,
    required_tee_types=[TEEType.SGX],
)
async def secure_key_management(request: Request):
    """
    Secure key management inside enclave.

    Generate, store, and use cryptographic keys that never
    leave the enclave's encrypted memory.
    """
    body = await request.json()
    operation = body.get("operation")
    key_name = body.get("key_name")

    if operation == "generate":
        # Generate new key inside enclave
        import secrets
        new_key = secrets.token_bytes(32)

        # Seal to enclave
        await sealed_storage.store(f"key_{key_name}", new_key)

        return {
            "success": True,
            "operation": "generate",
            "key_name": key_name,
        }

    elif operation == "sign":
        # Sign data with sealed key
        data = base64.b64decode(body.get("data", ""))

        try:
            key = await sealed_storage.load(f"key_{key_name}")

            import hashlib
            import hmac
            signature = hmac.new(key, data, hashlib.sha256).digest()

            return {
                "success": True,
                "signature": base64.b64encode(signature).decode(),
            }
        except Exception as e:
            raise HTTPException(status_code=404, detail=f"Key not found: {e}")

    elif operation == "verify":
        data = base64.b64decode(body.get("data", ""))
        signature = base64.b64decode(body.get("signature", ""))

        try:
            key = await sealed_storage.load(f"key_{key_name}")

            import hashlib
            import hmac
            expected = hmac.new(key, data, hashlib.sha256).digest()

            return {
                "success": True,
                "valid": hmac.compare_digest(signature, expected),
            }
        except Exception as e:
            raise HTTPException(status_code=404, detail=f"Key not found: {e}")

    else:
        raise HTTPException(status_code=400, detail="Invalid operation")


# Helper to generate Gramine manifest
def generate_manifest():
    """Generate Gramine manifest for this application."""
    helper = GramineManifestHelper(
        entrypoint="/app/shield-api",
        enclave_size="512M",
        thread_num=16,
        enable_edmm=True,  # Enable dynamic memory (SGX2)
    )
    return helper.generate()


if __name__ == "__main__":
    import sys

    if "--manifest" in sys.argv:
        print(generate_manifest())
    else:
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8000)
