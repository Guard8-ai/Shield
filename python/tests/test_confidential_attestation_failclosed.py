"""
RT2-4: the Python TEE attestation providers must be fail-closed.

They parse evidence and compare measurement fields but never verify the quote /
token signature or certificate chain. Returning verified=True from such
unverified evidence let an attacker forge evidence and release keys via
TEEKeyManager. The providers must now return verified=False by default and only
accept unverified evidence when explicitly constructed with
allow_insecure_demo=True (which warns).
"""

import asyncio
import base64
import json
import time

import pytest

from shield.integrations.confidential.gcp_sev import SEVAttestationProvider


def _b64url(obj) -> str:
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _fake_sev_token() -> bytes:
    """A structurally valid GCP Confidential-VM JWT with a bogus signature."""
    header = _b64url({"alg": "RS256", "typ": "JWT"})
    payload = _b64url(
        {
            "google": {"confidential_vm": True, "project_id": "proj"},
            "sev_snp": {"measurement": "deadbeef"},
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
    )
    # The third segment is the signature — attacker-controlled / never checked.
    return f"{header}.{payload}.{'A' * 43}".encode()


def test_sev_fail_closed_by_default():
    provider = SEVAttestationProvider()
    result = asyncio.run(provider.verify(_fake_sev_token()))
    assert result.verified is False
    assert "does NOT cryptographically verify" in (result.error or "")


def test_sev_demo_mode_accepts_unverified_and_warns():
    with pytest.warns(UserWarning, match="(?i)insecure"):
        provider = SEVAttestationProvider(allow_insecure_demo=True)
    result = asyncio.run(provider.verify(_fake_sev_token()))
    # Demo mode is explicitly insecure: it accepts the unverified evidence.
    assert result.verified is True


def test_all_providers_warn_in_demo_mode():
    from shield.integrations.confidential.azure_maa import MAAAttestationProvider
    from shield.integrations.confidential.aws_nitro import NitroAttestationProvider
    from shield.integrations.confidential.intel_sgx import SGXAttestationProvider

    with pytest.warns(UserWarning, match="(?i)insecure"):
        MAAAttestationProvider(attestation_uri="https://example", allow_insecure_demo=True)
    with pytest.warns(UserWarning, match="(?i)insecure"):
        NitroAttestationProvider(allow_insecure_demo=True)
    with pytest.warns(UserWarning, match="(?i)insecure"):
        SGXAttestationProvider(allow_insecure_demo=True)


def test_providers_do_not_warn_by_default():
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any UserWarning would fail the test
        SEVAttestationProvider()
