"""
AWS Nitro Parent Instance Client

This example shows how to communicate with a Nitro Enclave from the
parent EC2 instance using vsock.

The parent instance:
1. Receives external HTTP requests
2. Forwards them to the enclave via vsock
3. Returns encrypted responses to clients

Usage:
    python parent_instance.py

Requirements:
    - Running on EC2 instance with Nitro Enclave running
    - nitro-cli installed
"""

import asyncio
import base64
import json
import struct
import socket
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

from shield import Shield
from shield.integrations.confidential import (
    NitroAttestationProvider,
    TEEKeyManager,
)
from shield.integrations.confidential.aws_nitro import NitroVsockClient

app = FastAPI(
    title="Nitro Enclave Proxy",
    description="Parent instance proxy for Nitro Enclave",
)

# Configuration
ENCLAVE_CID = 16  # Enclave CID (get from nitro-cli describe-enclaves)
ENCLAVE_PORT = 5000

# Attestation provider for verifying enclave responses
provider = NitroAttestationProvider()


class EnclaveClient:
    """Client for communicating with the Nitro Enclave."""

    def __init__(self, cid: int = 16, port: int = 5000):
        self.cid = cid
        self.port = port

    async def send_request(
        self,
        method: str,
        path: str,
        headers: dict = None,
        body: bytes = None,
    ) -> dict:
        """Send HTTP request to enclave via vsock."""
        try:
            sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((self.cid, self.port))

            request_data = {
                "method": method,
                "path": path,
                "headers": headers or {},
                "body": base64.b64encode(body).decode() if body else None,
            }

            request_bytes = json.dumps(request_data).encode()
            length = struct.pack(">I", len(request_bytes))
            sock.sendall(length + request_bytes)

            response_length = struct.unpack(">I", sock.recv(4))[0]
            response_bytes = b""
            while len(response_bytes) < response_length:
                chunk = sock.recv(response_length - len(response_bytes))
                if not chunk:
                    raise Exception("Connection closed")
                response_bytes += chunk

            sock.close()
            return json.loads(response_bytes)

        except socket.error as e:
            raise HTTPException(
                status_code=503,
                detail=f"Enclave communication failed: {e}",
            )

    async def get_attestation(self, user_data: bytes = None) -> bytes:
        """Get attestation document from enclave."""
        response = await self.send_request(
            method="GET",
            path="/api/attestation",
            headers={"X-User-Data": base64.b64encode(user_data or b"").decode()},
        )

        if "attestation" in response.get("body", {}):
            return base64.b64decode(response["body"]["attestation"])

        raise HTTPException(
            status_code=500,
            detail="Failed to get enclave attestation",
        )


enclave_client = EnclaveClient(cid=ENCLAVE_CID, port=ENCLAVE_PORT)


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy", "role": "parent-instance"}


@app.get("/enclave/status")
async def enclave_status():
    """Check enclave status and get attestation."""
    try:
        attestation = await enclave_client.get_attestation()
        result = await provider.verify(attestation)

        return {
            "enclave_running": True,
            "verified": result.verified,
            "measurements": result.measurements,
            "claims": result.claims,
        }
    except Exception as e:
        return {
            "enclave_running": False,
            "error": str(e),
        }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_to_enclave(request: Request, path: str):
    """
    Proxy all requests to the enclave.

    This endpoint forwards requests to the enclave via vsock
    and returns the encrypted response.
    """
    body = await request.body() if request.method in ["POST", "PUT"] else None

    headers = dict(request.headers)

    response = await enclave_client.send_request(
        method=request.method,
        path=f"/{path}",
        headers=headers,
        body=body,
    )

    return JSONResponse(
        content=response.get("body", {}),
        status_code=response.get("status", 200),
        headers=response.get("headers", {}),
    )


# KMS integration for getting encryption keys
class KMSKeyProvider:
    """
    AWS KMS integration for key release based on enclave attestation.

    Uses KMS key policies that require valid attestation documents.
    """

    def __init__(self, key_id: str, region: str = "us-east-1"):
        self.key_id = key_id
        self.region = region
        self._kms_client = None

    def _ensure_client(self):
        if self._kms_client is None:
            try:
                import boto3
                self._kms_client = boto3.client("kms", region_name=self.region)
            except ImportError:
                raise Exception("boto3 required. Install with: pip install boto3")

    async def decrypt_for_enclave(
        self,
        ciphertext: bytes,
        attestation_doc: bytes,
    ) -> bytes:
        """
        Decrypt data using KMS with attestation.

        The KMS key policy must allow decryption only when a valid
        attestation document is provided.
        """
        self._ensure_client()

        response = self._kms_client.decrypt(
            KeyId=self.key_id,
            CiphertextBlob=ciphertext,
            Recipient={
                "AttestationDocument": attestation_doc,
                "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
            },
        )

        return response["Plaintext"]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
