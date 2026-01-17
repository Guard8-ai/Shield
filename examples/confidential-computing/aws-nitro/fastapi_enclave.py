"""
AWS Nitro Enclave FastAPI Example

This example shows how to run a Shield-protected FastAPI application
inside an AWS Nitro Enclave with attestation verification.

Deployment:
    1. Build enclave image: nitro-cli build-enclave --docker-uri shield-api:latest
    2. Run enclave: nitro-cli run-enclave --eif-path shield-api.eif --cpu-count 2 --memory 512
    3. Parent instance communicates via vsock

Requirements:
    - EC2 instance with Nitro Enclave support (.metal or .xlarge)
    - nitro-cli installed
    - Docker for building enclave images
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
    NitroAttestationProvider,
    AttestationMiddleware,
    AttestationRouter,
    TEEKeyManager,
    requires_attestation,
    TEEType,
)

# Initialize FastAPI app
app = FastAPI(
    title="Shield Nitro Enclave API",
    description="Secure API running inside AWS Nitro Enclave",
)

# Initialize attestation provider with expected PCR values
# PCR0 = enclave image measurement
# PCR1 = kernel measurement
# PCR2 = application measurement
provider = NitroAttestationProvider(
    expected_pcrs={
        # Replace with your actual PCR values from nitro-cli describe-eif
        # 0: "your_pcr0_value_here",
    },
    max_age_seconds=300,
)

# Initialize key manager with attestation requirement
key_manager = TEEKeyManager(
    password="your-secure-password",  # In production, get from KMS after attestation
    service="nitro-enclave-api",
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

# Add Shield encryption middleware
app.add_middleware(
    ShieldMiddleware,
    password="your-secure-password",
    service="nitro-enclave-api",
    exclude_routes=["/health", "/attestation"],
)

# Include attestation router
attestation_router = AttestationRouter(provider=provider)
app.include_router(attestation_router.router, prefix="/api")


@app.get("/health")
async def health():
    """Health check endpoint (no attestation required)."""
    return {"status": "healthy", "environment": "nitro-enclave"}


@app.get("/secure/data")
async def get_secure_data(request: Request):
    """
    Get secure data (requires attestation).

    The attestation middleware verifies the client's attestation token
    before this handler is called.
    """
    attestation = getattr(request.state, "attestation", None)

    if attestation:
        return {
            "message": "This data is from inside a Nitro Enclave",
            "client_tee_type": attestation.tee_type.value,
            "client_measurements": attestation.measurements,
        }

    return {"message": "Secure data"}


@app.post("/secure/encrypt")
@requires_attestation(
    provider=provider,
    required_tee_types=[TEEType.NITRO],
)
async def encrypt_data(request: Request):
    """
    Encrypt data inside the enclave.

    Only clients running in verified Nitro Enclaves can use this endpoint.
    """
    body = await request.json()
    data = body.get("data", "").encode()

    # Get attestation-bound key
    attestation = request.state.attestation
    key = await key_manager.get_key(
        attestation.raw_evidence,
        key_id="encryption",
    )

    # Create Shield instance with derived key
    shield = Shield.__new__(Shield)
    shield._key = key
    shield._service = "nitro-enclave-api"

    encrypted = shield.encrypt(data)

    return {
        "encrypted": base64.b64encode(encrypted).decode(),
        "key_id": "encryption",
    }


@app.post("/secure/decrypt")
@requires_attestation(
    provider=provider,
    required_tee_types=[TEEType.NITRO],
)
async def decrypt_data(request: Request):
    """Decrypt data inside the enclave."""
    body = await request.json()
    encrypted = base64.b64decode(body.get("encrypted", ""))

    attestation = request.state.attestation
    key = await key_manager.get_key(
        attestation.raw_evidence,
        key_id="encryption",
    )

    shield = Shield.__new__(Shield)
    shield._key = key
    shield._service = "nitro-enclave-api"

    try:
        decrypted = shield.decrypt(encrypted)
        return {"decrypted": decrypted.decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {e}")


# Vsock server for communication with parent instance
async def run_vsock_server(app_instance, port: int = 5000):
    """
    Run vsock server for parent instance communication.

    In production, the enclave listens on vsock and the parent
    forwards HTTP requests through this channel.
    """
    from shield.integrations.confidential.aws_nitro import NitroVsockServer

    async def handle_request(data: bytes) -> bytes:
        """Handle HTTP request from parent."""
        # Parse HTTP request from parent
        request_data = json.loads(data)

        # Process request (simplified - in production use proper HTTP parsing)
        path = request_data.get("path", "/")
        method = request_data.get("method", "GET")
        headers = request_data.get("headers", {})
        body = request_data.get("body")

        # Create mock response (in production, route to FastAPI)
        response = {
            "status": 200,
            "body": {"message": f"Processed {method} {path}"},
        }

        return json.dumps(response).encode()

    server = NitroVsockServer(port=port, handler=handle_request)
    await server.start()


if __name__ == "__main__":
    import uvicorn

    # In enclave, run with vsock
    # Outside enclave (for testing), run normally
    uvicorn.run(app, host="0.0.0.0", port=8000)
