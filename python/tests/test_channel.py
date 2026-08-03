"""ShieldChannel session-key derivation tests."""

import json
import os

from shield.channel import ShieldChannel, ChannelConfig

_VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "tests", "channel_session_vectors.json"
)


def test_session_key_depends_on_service():
    """Same password/salt/contributions but a different service must yield a
    different session key, so a shared secret provisioned for one service cannot
    establish a channel for another (domain separation)."""
    salt = b"\x07" * 16
    contribution = b"\x09" * 32

    key_a = ShieldChannel._compute_session_key(
        ChannelConfig("same-password", "service-a"), salt, contribution, contribution
    )
    key_b = ShieldChannel._compute_session_key(
        ChannelConfig("same-password", "service-b"), salt, contribution, contribution
    )

    assert key_a != key_b, "session key must be bound to the service identifier"


def test_channel_session_conformance_vectors():
    """Reproduce the shared cross-language channel session-key vectors byte-for-
    byte. Rust (shield-core) is the source of truth; Go/JS/Python/Android all
    read tests/channel_session_vectors.json and must match. This anchors
    PAKEExchange.derive/combine and the session mix against silent divergence."""
    with open(_VECTORS_PATH, "rb") as fh:
        doc = json.load(fh)

    for vec in doc["vectors"]:
        config = ChannelConfig(vec["password"], vec["service"])
        config.iterations = vec["iterations"]
        session_key = ShieldChannel._compute_session_key(
            config,
            bytes.fromhex(vec["salt_hex"]),
            bytes.fromhex(vec["local_contribution_hex"]),
            bytes.fromhex(vec["remote_contribution_hex"]),
        )
        assert session_key.hex() == vec["expected_session_key_hex"], vec["name"]
