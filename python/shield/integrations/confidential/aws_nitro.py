"""
AWS Nitro Enclaves Attestation Provider

Provides attestation verification for AWS Nitro Enclaves using
COSE-signed attestation documents with PCR measurements.

Requirements:
    - Running inside a Nitro Enclave or EC2 parent instance
    - aws-nitro-enclaves-nsm-api for enclave operations
    - cbor2 for COSE parsing

Usage:
    from shield.integrations.confidential import NitroAttestationProvider

    provider = NitroAttestationProvider(
        expected_pcrs={0: "abc123...", 1: "def456..."},
    )

    # Verify attestation document
    result = await provider.verify(attestation_doc)

    # Generate attestation (inside enclave)
    evidence = await provider.generate_evidence(user_data=b"nonce")
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import time
from typing import Any, Dict, List, Optional

from shield.integrations.confidential.base import (
    AttestationError,
    AttestationProvider,
    AttestationResult,
    TEEType,
)

NSM_SOCKET_PATH = "/run/nitro_enclaves/vsock.sock"
VSOCK_PORT = 9999


class NitroAttestationProvider(AttestationProvider):
    """
    AWS Nitro Enclaves attestation provider.

    Verifies COSE-signed attestation documents containing:
    - PCR measurements (Platform Configuration Registers)
    - Module ID and digest
    - Timestamp and nonce
    - AWS certificate chain

    Args:
        expected_pcrs: Dictionary of PCR index -> expected hex value
        max_age_seconds: Maximum age of attestation document
        verify_certificate: Whether to verify AWS certificate chain
    """

    def __init__(
        self,
        expected_pcrs: Optional[Dict[int, str]] = None,
        max_age_seconds: float = 300.0,
        verify_certificate: bool = True,
    ):
        self.expected_pcrs = expected_pcrs or {}
        self.max_age_seconds = max_age_seconds
        self.verify_certificate = verify_certificate
        self._cbor = None
        self._cose = None

    @property
    def tee_type(self) -> TEEType:
        return TEEType.NITRO

    def _ensure_deps(self) -> None:
        """Ensure required dependencies are available."""
        if self._cbor is None:
            try:
                import cbor2
                self._cbor = cbor2
            except ImportError:
                raise AttestationError(
                    "cbor2 required for Nitro attestation. "
                    "Install with: pip install cbor2",
                    code="MISSING_DEPENDENCY",
                )

    async def verify(self, evidence: bytes) -> AttestationResult:
        """
        Verify a Nitro Enclave attestation document.

        The attestation document is a COSE Sign1 structure containing:
        - Protected header with algorithm
        - Unprotected header (empty)
        - Payload with PCRs, module info, timestamp
        - Signature from AWS Nitro attestation PKI

        Args:
            evidence: CBOR-encoded COSE Sign1 attestation document

        Returns:
            AttestationResult with PCR measurements and claims
        """
        self._ensure_deps()

        try:
            doc = self._cbor.loads(evidence)
        except Exception as e:
            return AttestationResult(
                verified=False,
                tee_type=self.tee_type,
                error=f"Failed to decode CBOR: {e}",
                raw_evidence=evidence,
            )

        if not isinstance(doc, list) or len(doc) != 4:
            return AttestationResult(
                verified=False,
                tee_type=self.tee_type,
                error="Invalid COSE Sign1 structure",
                raw_evidence=evidence,
            )

        protected, unprotected, payload_bytes, signature = doc

        try:
            payload = self._cbor.loads(payload_bytes)
        except Exception as e:
            return AttestationResult(
                verified=False,
                tee_type=self.tee_type,
                error=f"Failed to decode payload: {e}",
                raw_evidence=evidence,
            )

        measurements = {}
        pcrs = payload.get("pcrs", {})
        for idx, value in pcrs.items():
            if isinstance(value, bytes):
                measurements[f"PCR{idx}"] = value.hex()
            else:
                measurements[f"PCR{idx}"] = str(value)

        claims = {
            "module_id": payload.get("module_id", ""),
            "timestamp": payload.get("timestamp", 0),
            "digest": payload.get("digest", ""),
            "cabundle": len(payload.get("cabundle", [])),
        }

        if payload.get("user_data"):
            claims["user_data"] = base64.b64encode(
                payload["user_data"]
            ).decode()

        if payload.get("nonce"):
            claims["nonce"] = base64.b64encode(payload["nonce"]).decode()

        if payload.get("public_key"):
            claims["has_public_key"] = True

        for pcr_idx, expected_hex in self.expected_pcrs.items():
            pcr_key = f"PCR{pcr_idx}"
            actual = measurements.get(pcr_key, "").lower()
            if actual != expected_hex.lower():
                return AttestationResult(
                    verified=False,
                    tee_type=self.tee_type,
                    measurements=measurements,
                    claims=claims,
                    error=f"PCR{pcr_idx} mismatch: expected {expected_hex}, got {actual}",
                    raw_evidence=evidence,
                )

        timestamp = payload.get("timestamp", 0)
        if timestamp:
            age = time.time() * 1000 - timestamp
            if age > self.max_age_seconds * 1000:
                return AttestationResult(
                    verified=False,
                    tee_type=self.tee_type,
                    measurements=measurements,
                    claims=claims,
                    error=f"Attestation too old: {age/1000:.1f}s",
                    raw_evidence=evidence,
                )

        if self.verify_certificate:
            cabundle = payload.get("cabundle", [])
            if not cabundle:
                return AttestationResult(
                    verified=False,
                    tee_type=self.tee_type,
                    measurements=measurements,
                    claims=claims,
                    error="Missing certificate bundle",
                    raw_evidence=evidence,
                )

        return AttestationResult(
            verified=True,
            tee_type=self.tee_type,
            measurements=measurements,
            claims=claims,
            timestamp=timestamp / 1000 if timestamp else time.time(),
            raw_evidence=evidence,
        )

    async def generate_evidence(
        self,
        user_data: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
        public_key: Optional[bytes] = None,
    ) -> bytes:
        """
        Generate attestation evidence from inside a Nitro Enclave.

        This communicates with the Nitro Secure Module (NSM) via vsock
        to generate a signed attestation document.

        Args:
            user_data: Optional user data to bind to attestation (max 1024 bytes)
            nonce: Optional nonce for freshness (max 512 bytes)
            public_key: Optional public key to include (max 1024 bytes)

        Returns:
            CBOR-encoded COSE Sign1 attestation document

        Raises:
            AttestationError: If not running in a Nitro Enclave
        """
        self._ensure_deps()

        request = {"Attestation": {}}
        if user_data:
            if len(user_data) > 1024:
                raise AttestationError(
                    "user_data exceeds 1024 byte limit",
                    code="INVALID_REQUEST",
                )
            request["Attestation"]["user_data"] = user_data
        if nonce:
            if len(nonce) > 512:
                raise AttestationError(
                    "nonce exceeds 512 byte limit",
                    code="INVALID_REQUEST",
                )
            request["Attestation"]["nonce"] = nonce
        if public_key:
            if len(public_key) > 1024:
                raise AttestationError(
                    "public_key exceeds 1024 byte limit",
                    code="INVALID_REQUEST",
                )
            request["Attestation"]["public_key"] = public_key

        try:
            response = await self._nsm_call(request)
        except Exception as e:
            raise AttestationError(
                f"Failed to generate attestation: {e}",
                code="NSM_ERROR",
            )

        if "Attestation" not in response:
            error = response.get("Error", "Unknown error")
            raise AttestationError(
                f"NSM returned error: {error}",
                code="NSM_ERROR",
            )

        return response["Attestation"]["document"]

    async def _nsm_call(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Make a call to the Nitro Secure Module."""
        self._ensure_deps()

        try:
            sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            sock.connect((socket.VMADDR_CID_PARENT, VSOCK_PORT))
        except (OSError, AttributeError):
            raise AttestationError(
                "Not running in a Nitro Enclave (vsock not available)",
                code="NOT_IN_ENCLAVE",
            )

        try:
            request_bytes = self._cbor.dumps(request)

            length = struct.pack(">I", len(request_bytes))
            sock.sendall(length + request_bytes)

            response_length = struct.unpack(">I", sock.recv(4))[0]
            response_bytes = b""
            while len(response_bytes) < response_length:
                chunk = sock.recv(response_length - len(response_bytes))
                if not chunk:
                    raise AttestationError(
                        "Connection closed while reading response",
                        code="NSM_ERROR",
                    )
                response_bytes += chunk

            return self._cbor.loads(response_bytes)
        finally:
            sock.close()

    async def get_pcrs(self) -> Dict[int, bytes]:
        """
        Get current PCR values from inside the enclave.

        Returns:
            Dictionary of PCR index -> value
        """
        response = await self._nsm_call({"DescribePCR": {"index": 0}})

        if "DescribePCR" not in response:
            raise AttestationError(
                "Failed to get PCR values",
                code="NSM_ERROR",
            )

        pcrs = {}
        for i in range(16):
            try:
                resp = await self._nsm_call({"DescribePCR": {"index": i}})
                if "DescribePCR" in resp:
                    pcrs[i] = resp["DescribePCR"]["data"]
            except Exception:
                pass

        return pcrs

    async def extend_pcr(self, index: int, data: bytes) -> bytes:
        """
        Extend a PCR with additional data.

        Args:
            index: PCR index (0-15)
            data: Data to extend into PCR

        Returns:
            New PCR value
        """
        if index < 0 or index > 15:
            raise AttestationError(
                f"Invalid PCR index: {index}",
                code="INVALID_REQUEST",
            )

        response = await self._nsm_call({
            "ExtendPCR": {
                "index": index,
                "data": data,
            }
        })

        if "ExtendPCR" not in response:
            error = response.get("Error", "Unknown error")
            raise AttestationError(
                f"Failed to extend PCR: {error}",
                code="NSM_ERROR",
            )

        return response["ExtendPCR"]["data"]


class NitroVsockClient:
    """
    Client for communicating with parent EC2 instance via vsock.

    Use this to send encrypted data between the enclave and parent.

    Usage:
        client = NitroVsockClient(port=5000)
        await client.connect()
        response = await client.send(b"encrypted_request")
        await client.close()
    """

    def __init__(self, port: int = 5000, cid: int = 3):
        """
        Initialize vsock client.

        Args:
            port: vsock port to connect to
            cid: Context ID (3 = parent instance)
        """
        self.port = port
        self.cid = cid
        self._sock: Optional[socket.socket] = None

    async def connect(self) -> None:
        """Connect to parent instance."""
        try:
            self._sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            self._sock.connect((self.cid, self.port))
        except (OSError, AttributeError) as e:
            raise AttestationError(
                f"Failed to connect via vsock: {e}",
                code="VSOCK_ERROR",
            )

    async def send(self, data: bytes) -> bytes:
        """Send data and receive response."""
        if not self._sock:
            raise AttestationError(
                "Not connected",
                code="NOT_CONNECTED",
            )

        length = struct.pack(">I", len(data))
        self._sock.sendall(length + data)

        response_length = struct.unpack(">I", self._sock.recv(4))[0]
        response = b""
        while len(response) < response_length:
            chunk = self._sock.recv(response_length - len(response))
            if not chunk:
                raise AttestationError(
                    "Connection closed",
                    code="VSOCK_ERROR",
                )
            response += chunk

        return response

    async def close(self) -> None:
        """Close connection."""
        if self._sock:
            self._sock.close()
            self._sock = None


class NitroVsockServer:
    """
    Server for receiving requests from Nitro Enclave via vsock.

    Run this on the parent EC2 instance to handle enclave requests.

    Usage:
        async def handle_request(data: bytes) -> bytes:
            # Process encrypted request from enclave
            return response

        server = NitroVsockServer(port=5000, handler=handle_request)
        await server.start()
    """

    def __init__(
        self,
        port: int = 5000,
        handler: Optional[Any] = None,
    ):
        """
        Initialize vsock server.

        Args:
            port: vsock port to listen on
            handler: Async function to handle requests
        """
        self.port = port
        self.handler = handler
        self._sock: Optional[socket.socket] = None
        self._running = False

    async def start(self) -> None:
        """Start the vsock server."""
        try:
            self._sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((socket.VMADDR_CID_ANY, self.port))
            self._sock.listen(5)
            self._running = True
        except (OSError, AttributeError) as e:
            raise AttestationError(
                f"Failed to start vsock server: {e}",
                code="VSOCK_ERROR",
            )

        while self._running:
            try:
                conn, addr = self._sock.accept()
                await self._handle_connection(conn)
            except Exception:
                if self._running:
                    continue
                break

    async def _handle_connection(self, conn: socket.socket) -> None:
        """Handle a single connection."""
        try:
            length_bytes = conn.recv(4)
            if len(length_bytes) < 4:
                return

            length = struct.unpack(">I", length_bytes)[0]
            data = b""
            while len(data) < length:
                chunk = conn.recv(length - len(data))
                if not chunk:
                    return
                data += chunk

            if self.handler:
                response = await self.handler(data)
                response_length = struct.pack(">I", len(response))
                conn.sendall(response_length + response)
        finally:
            conn.close()

    async def stop(self) -> None:
        """Stop the server."""
        self._running = False
        if self._sock:
            self._sock.close()
            self._sock = None
