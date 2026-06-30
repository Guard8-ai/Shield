"""ShieldChannel session-key derivation tests."""

from shield.channel import ShieldChannel, ChannelConfig


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
