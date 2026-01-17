"""
Intel SGX Attestation Provider

Provides attestation verification for Intel SGX enclaves using
DCAP (Data Center Attestation Primitives) or EPID.

Requirements:
    - Running inside an SGX enclave (via Gramine or Occlum)
    - Intel SGX DCAP libraries for quote generation
    - PCCS (Provisioning Certificate Caching Service) for verification

Usage:
    from shield.integrations.confidential import SGXAttestationProvider

    provider = SGXAttestationProvider(
        expected_mrenclave="abc123...",
        expected_mrsigner="def456...",
    )

    # Verify SGX quote
    result = await provider.verify(quote)

    # Generate quote (inside enclave)
    evidence = await provider.generate_evidence(report_data=b"nonce")
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import time
from typing import Any, Dict, List, Optional

from shield.integrations.confidential.base import (
    AttestationError,
    AttestationProvider,
    AttestationResult,
    TEEType,
)

SGX_REPORT_BODY_SIZE = 384
SGX_QUOTE_HEADER_SIZE = 48


class SGXAttestationProvider(AttestationProvider):
    """
    Intel SGX attestation provider.

    Verifies DCAP quotes containing:
    - MRENCLAVE (enclave measurement)
    - MRSIGNER (signer measurement)
    - ISV Product ID and SVN
    - Report data (user-provided)

    Args:
        expected_mrenclave: Expected MRENCLAVE value (hex)
        expected_mrsigner: Expected MRSIGNER value (hex)
        min_isv_svn: Minimum ISV SVN version
        verify_with_pccs: Whether to verify quote with Intel PCCS
        pccs_url: PCCS URL for quote verification
    """

    def __init__(
        self,
        expected_mrenclave: Optional[str] = None,
        expected_mrsigner: Optional[str] = None,
        min_isv_svn: int = 0,
        verify_with_pccs: bool = False,
        pccs_url: str = "https://localhost:8081/sgx/certification/v4",
    ):
        self.expected_mrenclave = expected_mrenclave
        self.expected_mrsigner = expected_mrsigner
        self.min_isv_svn = min_isv_svn
        self.verify_with_pccs = verify_with_pccs
        self.pccs_url = pccs_url

    @property
    def tee_type(self) -> TEEType:
        return TEEType.SGX

    async def verify(self, evidence: bytes) -> AttestationResult:
        """
        Verify an SGX DCAP quote.

        Quote structure:
        - Header (48 bytes): version, att_key_type, tee_type, etc.
        - Report Body (384 bytes): MRENCLAVE, MRSIGNER, etc.
        - Signature data (variable)

        Args:
            evidence: Raw SGX quote bytes

        Returns:
            AttestationResult with measurements and claims
        """
        if len(evidence) < SGX_QUOTE_HEADER_SIZE + SGX_REPORT_BODY_SIZE:
            return AttestationResult(
                verified=False,
                tee_type=self.tee_type,
                error=f"Quote too small: {len(evidence)} bytes",
                raw_evidence=evidence,
            )

        try:
            header = self._parse_quote_header(evidence[:SGX_QUOTE_HEADER_SIZE])
            report_body = self._parse_report_body(
                evidence[SGX_QUOTE_HEADER_SIZE:SGX_QUOTE_HEADER_SIZE + SGX_REPORT_BODY_SIZE]
            )
        except Exception as e:
            return AttestationResult(
                verified=False,
                tee_type=self.tee_type,
                error=f"Failed to parse quote: {e}",
                raw_evidence=evidence,
            )

        measurements = {
            "MRENCLAVE": report_body["mrenclave"],
            "MRSIGNER": report_body["mrsigner"],
            "REPORT_DATA": report_body["report_data"],
            "CPU_SVN": report_body["cpu_svn"],
        }

        claims = {
            "quote_version": header["version"],
            "att_key_type": header["att_key_type"],
            "tee_type": header["tee_type"],
            "isv_prod_id": report_body["isv_prod_id"],
            "isv_svn": report_body["isv_svn"],
            "attributes": report_body["attributes"],
            "misc_select": report_body["misc_select"],
        }

        if self.expected_mrenclave:
            actual = measurements["MRENCLAVE"].lower()
            if actual != self.expected_mrenclave.lower():
                return AttestationResult(
                    verified=False,
                    tee_type=self.tee_type,
                    measurements=measurements,
                    claims=claims,
                    error=f"MRENCLAVE mismatch: expected {self.expected_mrenclave}",
                    raw_evidence=evidence,
                )

        if self.expected_mrsigner:
            actual = measurements["MRSIGNER"].lower()
            if actual != self.expected_mrsigner.lower():
                return AttestationResult(
                    verified=False,
                    tee_type=self.tee_type,
                    measurements=measurements,
                    claims=claims,
                    error=f"MRSIGNER mismatch: expected {self.expected_mrsigner}",
                    raw_evidence=evidence,
                )

        if report_body["isv_svn"] < self.min_isv_svn:
            return AttestationResult(
                verified=False,
                tee_type=self.tee_type,
                measurements=measurements,
                claims=claims,
                error=f"ISV SVN {report_body['isv_svn']} below minimum {self.min_isv_svn}",
                raw_evidence=evidence,
            )

        if self.verify_with_pccs:
            try:
                await self._verify_with_pccs(evidence)
            except Exception as e:
                return AttestationResult(
                    verified=False,
                    tee_type=self.tee_type,
                    measurements=measurements,
                    claims=claims,
                    error=f"PCCS verification failed: {e}",
                    raw_evidence=evidence,
                )

        return AttestationResult(
            verified=True,
            tee_type=self.tee_type,
            measurements=measurements,
            claims=claims,
            timestamp=time.time(),
            raw_evidence=evidence,
        )

    def _parse_quote_header(self, data: bytes) -> Dict[str, Any]:
        """Parse SGX quote header."""
        version, att_key_type, tee_type, reserved, vendor_id = struct.unpack(
            "<HHHI16s", data[:28]
        )

        user_data = data[28:48]

        return {
            "version": version,
            "att_key_type": att_key_type,
            "tee_type": tee_type,
            "vendor_id": vendor_id.hex(),
            "user_data": user_data.hex(),
        }

    def _parse_report_body(self, data: bytes) -> Dict[str, Any]:
        """Parse SGX report body."""
        cpu_svn = data[0:16].hex()
        misc_select = struct.unpack("<I", data[16:20])[0]
        reserved1 = data[20:48]
        attributes = data[48:64].hex()
        mrenclave = data[64:96].hex()
        reserved2 = data[96:128]
        mrsigner = data[128:160].hex()
        reserved3 = data[160:256]
        isv_prod_id = struct.unpack("<H", data[256:258])[0]
        isv_svn = struct.unpack("<H", data[258:260])[0]
        reserved4 = data[260:320]
        report_data = data[320:384].hex()

        return {
            "cpu_svn": cpu_svn,
            "misc_select": misc_select,
            "attributes": attributes,
            "mrenclave": mrenclave,
            "mrsigner": mrsigner,
            "isv_prod_id": isv_prod_id,
            "isv_svn": isv_svn,
            "report_data": report_data,
        }

    async def _verify_with_pccs(self, quote: bytes) -> None:
        """Verify quote with Intel PCCS."""
        from urllib.request import Request, urlopen
        from urllib.error import URLError

        url = f"{self.pccs_url}/quote"

        request = Request(
            url,
            data=quote,
            headers={"Content-Type": "application/octet-stream"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=30) as response:
                if response.status != 200:
                    raise AttestationError(
                        f"PCCS returned status {response.status}",
                        code="PCCS_ERROR",
                    )
        except URLError as e:
            raise AttestationError(
                f"Failed to contact PCCS: {e}",
                code="PCCS_ERROR",
            )

    async def generate_evidence(
        self,
        report_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Generate SGX quote from inside an enclave.

        This works with Gramine's /dev/attestation interface.

        Args:
            report_data: User data to include in quote (64 bytes max)

        Returns:
            Raw SGX quote bytes

        Raises:
            AttestationError: If not running in an SGX enclave
        """
        user_report_data = report_data or b"\x00" * 64
        if len(user_report_data) < 64:
            user_report_data = user_report_data + b"\x00" * (64 - len(user_report_data))
        user_report_data = user_report_data[:64]

        gramine_paths = [
            "/dev/attestation/quote",
            "/dev/attestation/user_report_data",
        ]

        if all(os.path.exists(p) for p in gramine_paths):
            return await self._gramine_quote(user_report_data)

        occlum_path = "/dev/sgx"
        if os.path.exists(occlum_path):
            return await self._occlum_quote(user_report_data)

        raise AttestationError(
            "Not running in an SGX enclave. "
            "Gramine or Occlum attestation interface not found.",
            code="NOT_IN_ENCLAVE",
        )

    async def _gramine_quote(self, report_data: bytes) -> bytes:
        """Generate quote using Gramine's attestation interface."""
        try:
            with open("/dev/attestation/user_report_data", "wb") as f:
                f.write(report_data)

            with open("/dev/attestation/quote", "rb") as f:
                quote = f.read()

            return quote
        except Exception as e:
            raise AttestationError(
                f"Failed to generate Gramine quote: {e}",
                code="GRAMINE_ERROR",
            )

    async def _occlum_quote(self, report_data: bytes) -> bytes:
        """Generate quote using Occlum's interface."""
        try:
            import ctypes

            libocclum_pal = ctypes.CDLL("libocclum-pal.so")

            quote_size = ctypes.c_uint32()
            report_data_arr = (ctypes.c_uint8 * 64).from_buffer_copy(report_data)

            ret = libocclum_pal.occlum_pal_get_quote_size(ctypes.byref(quote_size))
            if ret != 0:
                raise AttestationError(
                    f"Failed to get quote size: {ret}",
                    code="OCCLUM_ERROR",
                )

            quote_buf = (ctypes.c_uint8 * quote_size.value)()

            ret = libocclum_pal.occlum_pal_generate_quote(
                report_data_arr,
                quote_buf,
                quote_size,
            )
            if ret != 0:
                raise AttestationError(
                    f"Failed to generate quote: {ret}",
                    code="OCCLUM_ERROR",
                )

            return bytes(quote_buf)
        except OSError:
            raise AttestationError(
                "Occlum PAL library not found",
                code="OCCLUM_ERROR",
            )


class SealedStorage:
    """
    SGX sealed storage for persistent secrets.

    Data sealed to enclave identity can only be unsealed by the
    same enclave (MRENCLAVE) or same signer (MRSIGNER).

    Usage:
        storage = SealedStorage(seal_to="mrenclave")

        # Seal data
        sealed = await storage.seal(b"secret data")

        # Unseal data (only works in same enclave)
        data = await storage.unseal(sealed)
    """

    def __init__(
        self,
        seal_to: str = "mrenclave",
        storage_path: str = "/data/sealed",
    ):
        """
        Initialize sealed storage.

        Args:
            seal_to: Seal to "mrenclave" or "mrsigner"
            storage_path: Path to store sealed data
        """
        if seal_to not in ("mrenclave", "mrsigner"):
            raise ValueError("seal_to must be 'mrenclave' or 'mrsigner'")

        self.seal_to = seal_to
        self.storage_path = storage_path

    async def seal(self, data: bytes) -> bytes:
        """
        Seal data to enclave identity.

        Uses Gramine's sealing interface if available.

        Args:
            data: Data to seal

        Returns:
            Sealed data blob
        """
        seal_path = f"/dev/attestation/keys/{self.seal_to}"

        if os.path.exists(seal_path):
            try:
                with open(seal_path, "rb") as f:
                    seal_key = f.read(16)

                from shield import Shield
                s = Shield.__new__(Shield)
                s._key = hashlib.sha256(seal_key).digest()
                s._service = f"sgx-sealed-{self.seal_to}"

                return s.encrypt(data)
            except Exception as e:
                raise AttestationError(
                    f"Failed to seal data: {e}",
                    code="SEAL_ERROR",
                )

        raise AttestationError(
            "Gramine sealing interface not available",
            code="NOT_IN_ENCLAVE",
        )

    async def unseal(self, sealed_data: bytes) -> bytes:
        """
        Unseal data.

        Args:
            sealed_data: Previously sealed data

        Returns:
            Original data

        Raises:
            AttestationError: If unsealing fails
        """
        seal_path = f"/dev/attestation/keys/{self.seal_to}"

        if os.path.exists(seal_path):
            try:
                with open(seal_path, "rb") as f:
                    seal_key = f.read(16)

                from shield import Shield
                s = Shield.__new__(Shield)
                s._key = hashlib.sha256(seal_key).digest()
                s._service = f"sgx-sealed-{self.seal_to}"

                return s.decrypt(sealed_data)
            except Exception as e:
                raise AttestationError(
                    f"Failed to unseal data: {e}",
                    code="UNSEAL_ERROR",
                )

        raise AttestationError(
            "Gramine sealing interface not available",
            code="NOT_IN_ENCLAVE",
        )

    async def store(self, key: str, data: bytes) -> None:
        """
        Seal and store data with a key.

        Args:
            key: Storage key
            data: Data to store
        """
        os.makedirs(self.storage_path, exist_ok=True)
        sealed = await self.seal(data)

        key_hash = hashlib.sha256(key.encode()).hexdigest()[:32]
        path = os.path.join(self.storage_path, key_hash)

        with open(path, "wb") as f:
            f.write(sealed)

    async def load(self, key: str) -> bytes:
        """
        Load and unseal data by key.

        Args:
            key: Storage key

        Returns:
            Original data

        Raises:
            AttestationError: If key not found or unsealing fails
        """
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:32]
        path = os.path.join(self.storage_path, key_hash)

        if not os.path.exists(path):
            raise AttestationError(
                f"Sealed data not found: {key}",
                code="NOT_FOUND",
            )

        with open(path, "rb") as f:
            sealed = f.read()

        return await self.unseal(sealed)


class GramineManifestHelper:
    """
    Helper for generating Gramine manifest configurations.

    Usage:
        helper = GramineManifestHelper(
            entrypoint="/app/shield",
            enclave_size="256M",
        )

        manifest = helper.generate()
    """

    def __init__(
        self,
        entrypoint: str,
        enclave_size: str = "256M",
        thread_num: int = 8,
        enable_edmm: bool = False,
    ):
        self.entrypoint = entrypoint
        self.enclave_size = enclave_size
        self.thread_num = thread_num
        self.enable_edmm = enable_edmm

    def generate(self) -> str:
        """Generate Gramine manifest content."""
        manifest = f"""# Gramine manifest for Shield application
# Generated by shield.integrations.confidential

[loader]
entrypoint = "file:{{{{ gramine.libos }}}}"
log_level = "warning"

[loader.argv]
argv0 = "{self.entrypoint}"

[loader.env]
LD_LIBRARY_PATH = "/lib:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu"

[libos]
entrypoint = "{self.entrypoint}"

[sys]
enable_sigterm_injection = true

[sgx]
debug = false
enclave_size = "{self.enclave_size}"
thread_num = {self.thread_num}
remote_attestation = "dcap"
enable_stats = false
edmm_enable = {"true" if self.enable_edmm else "false"}

[sgx.trusted_files]
entrypoint = "file:{self.entrypoint}"
libos = "file:{{{{ gramine.libos }}}}"
runtime = "file:{{{{ gramine.runtimedir() }}}}"

[fs.mounts]
type = "chroot"
path = "/lib"
uri = "file:{{{{ gramine.runtimedir() }}}}"
"""
        return manifest
