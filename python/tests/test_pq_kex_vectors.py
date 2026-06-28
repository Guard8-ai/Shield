"""Conformance test: Python must satisfy the shared cross-language PQ-KEX vectors.

The same tests/pq_kex_vectors.json is consumed by the Go binding
(go/shield/pqhybrid_test.go), so this file is what keeps the implementations
byte-identical.
"""

import json
from pathlib import Path

import pytest

from shield.pqhybrid import HybridPrivateKey


def _mlkem_available() -> bool:
    """Skip the PQ conformance vectors when the backend lacks ML-KEM-768
    (OpenSSL < 3.5, e.g. older Python wheels) instead of hard-failing."""
    try:
        HybridPrivateKey.generate()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _mlkem_available(),
    reason="ML-KEM-768 not supported by this cryptography/OpenSSL backend",
)

VECTORS_PATH = Path(__file__).resolve().parents[2] / "tests" / "pq_kex_vectors.json"


def load_vectors():
    doc = json.loads(VECTORS_PATH.read_text())
    return doc["vectors"]


@pytest.mark.parametrize("vec", load_vectors(), ids=lambda v: v["name"])
def test_pq_kex_vector(vec):
    bob = HybridPrivateKey.from_bytes(bytes.fromhex(vec["bob_private_hex"]))

    # Public bundle must match (confirms key encoding is identical cross-language).
    assert bob.public_key().to_bytes().hex() == vec["bob_public_bundle_hex"]

    # Accepting the recorded handshake must reproduce the recorded shared key.
    shared = bob.accept(bytes.fromhex(vec["handshake_hex"]))
    assert shared.hex() == vec["expected_shared_key_hex"]
