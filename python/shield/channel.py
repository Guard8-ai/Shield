"""
Shield Secure Channel - TLS/SSH-like secure transport using symmetric crypto.

Provides encrypted bidirectional communication with:
- PAKE-based handshake (no certificates needed)
- Forward secrecy via key ratcheting
- Message authentication and replay protection

Example:
    >>> from shield.channel import ShieldChannel, ChannelConfig
    >>>
    >>> # Both parties share a password
    >>> config = ChannelConfig("shared-secret", "my-service")
    >>>
    >>> # Server side
    >>> server = ShieldChannel.accept(conn, config)
    >>>
    >>> # Client side
    >>> client = ShieldChannel.connect(conn, config)
    >>>
    >>> # Send/receive with forward secrecy
    >>> client.send(b"Hello server!")
    >>> msg = server.recv()
"""

import hmac
import hashlib
import struct
import secrets
from typing import Optional, BinaryIO, Union
from dataclasses import dataclass

from shield.exchange import PAKEExchange
from shield.ratchet import RatchetSession


# Protocol constants
PROTOCOL_VERSION = 1
MAX_MESSAGE_SIZE = 16 * 1024 * 1024  # 16 MB

# Handshake message types
HANDSHAKE_CLIENT_HELLO = 1
HANDSHAKE_SERVER_HELLO = 2
HANDSHAKE_FINISHED = 3


@dataclass
class ChannelConfig:
    """Channel configuration."""
    password: str
    service: str
    iterations: int = 200000
    handshake_timeout_ms: int = 30000

    def with_iterations(self, iterations: int) -> 'ChannelConfig':
        """Set custom PBKDF2 iterations."""
        self.iterations = iterations
        return self

    def with_timeout(self, timeout_ms: int) -> 'ChannelConfig':
        """Set handshake timeout."""
        self.handshake_timeout_ms = timeout_ms
        return self


class ShieldChannel:
    """
    Shield secure channel for encrypted communication.

    Provides TLS-like security using only symmetric cryptography:
    - PAKE handshake establishes shared key from password
    - RatchetSession provides forward secrecy
    - All messages authenticated with HMAC
    """

    def __init__(self, stream: BinaryIO, session: RatchetSession, service: str):
        self._stream = stream
        self._session = session
        self._service = service

    @classmethod
    def connect(cls, stream: BinaryIO, config: ChannelConfig) -> 'ShieldChannel':
        """
        Connect as client (initiator).

        Performs PAKE handshake and establishes encrypted channel.

        Args:
            stream: Underlying transport (socket, etc.)
            config: Channel configuration with shared password

        Returns:
            Connected ShieldChannel
        """
        # Step 1: Generate client salt and send ClientHello
        client_salt = secrets.token_bytes(16)
        cls._send_handshake(stream, HANDSHAKE_CLIENT_HELLO, client_salt)

        # Step 2: Receive ServerHello (server's salt + contribution)
        server_hello = cls._recv_handshake(stream, HANDSHAKE_SERVER_HELLO)
        if len(server_hello) != 48:
            raise ValueError("Invalid ServerHello")

        # Extract final salt and server contribution
        final_salt = server_hello[:16]
        server_contribution = server_hello[16:48]

        # Step 3: Derive our contribution and send it
        client_contribution = PAKEExchange.derive(
            config.password, final_salt, "client", config.iterations
        )
        cls._send_handshake(stream, HANDSHAKE_FINISHED, client_contribution)

        # Compute session key
        session_key = cls._compute_session_key(
            config, final_salt, client_contribution, server_contribution
        )

        # Create ratchet session (client is initiator)
        session = RatchetSession(session_key, is_initiator=True)

        # Exchange confirmation messages
        cls._send_confirmation(stream, session_key, is_client=True)
        cls._verify_confirmation(stream, session_key, expect_client=False)

        return cls(stream, session, config.service)

    @classmethod
    def accept(cls, stream: BinaryIO, config: ChannelConfig) -> 'ShieldChannel':
        """
        Accept connection as server.

        Waits for client handshake and establishes encrypted channel.

        Args:
            stream: Underlying transport (socket, etc.)
            config: Channel configuration with shared password

        Returns:
            Connected ShieldChannel
        """
        # Step 1: Receive ClientHello (client's proposed salt)
        client_hello = cls._recv_handshake(stream, HANDSHAKE_CLIENT_HELLO)
        if len(client_hello) != 16:
            raise ValueError("Invalid ClientHello")

        # Mix client salt with server salt for freshness
        server_salt = secrets.token_bytes(16)
        final_salt = bytes(a ^ b for a, b in zip(server_salt, client_hello))

        # Derive server contribution
        server_contribution = PAKEExchange.derive(
            config.password, final_salt, "server", config.iterations
        )

        # Step 2: Send ServerHello (final salt + server contribution)
        server_hello = final_salt + server_contribution
        cls._send_handshake(stream, HANDSHAKE_SERVER_HELLO, server_hello)

        # Step 3: Receive client contribution
        client_finished = cls._recv_handshake(stream, HANDSHAKE_FINISHED)
        if len(client_finished) != 32:
            raise ValueError("Invalid Finished")

        client_contribution = client_finished

        # Compute session key
        session_key = cls._compute_session_key(
            config, final_salt, server_contribution, client_contribution
        )

        # Create ratchet session (server is not initiator)
        session = RatchetSession(session_key, is_initiator=False)

        # Exchange confirmation messages
        cls._verify_confirmation(stream, session_key, expect_client=True)
        cls._send_confirmation(stream, session_key, is_client=False)

        return cls(stream, session, config.service)

    def send(self, data: bytes) -> None:
        """
        Send encrypted message.

        Message is encrypted with current ratchet key, then key advances.
        """
        if len(data) > MAX_MESSAGE_SIZE:
            raise ValueError(f"Message too large: {len(data)} > {MAX_MESSAGE_SIZE}")

        encrypted = self._session.encrypt(data)
        self._write_frame(encrypted)

    def recv(self) -> bytes:
        """
        Receive and decrypt message.

        Verifies authentication and advances receive ratchet.
        """
        encrypted = self._read_frame()
        return self._session.decrypt(encrypted)

    @property
    def service(self) -> str:
        """Get service identifier."""
        return self._service

    @property
    def messages_sent(self) -> int:
        """Get send message count."""
        return self._session.send_counter

    @property
    def messages_received(self) -> int:
        """Get receive message count."""
        return self._session.recv_counter

    def close(self) -> None:
        """Close the channel."""
        self._stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # --- Internal helpers ---

    @staticmethod
    def _compute_session_key(
        config: ChannelConfig,
        salt: bytes,
        local_contribution: bytes,
        remote_contribution: bytes
    ) -> bytes:
        """Compute session key from contributions."""
        # Combine contributions
        base_key = PAKEExchange.combine(local_contribution, remote_contribution)

        # Mix in password-derived secret (not exchanged)
        password_key = PAKEExchange.derive(
            config.password, salt, "session", config.iterations
        )

        # Final session key = hash(base_key || password_key)
        combined = base_key + password_key
        return hashlib.sha256(combined).digest()

    @classmethod
    def _send_handshake(cls, stream: BinaryIO, msg_type: int, data: bytes) -> None:
        """Send handshake message."""
        frame = bytes([PROTOCOL_VERSION, msg_type])
        frame += struct.pack('>H', len(data))
        frame += data
        stream.write(frame)
        stream.flush()

    @classmethod
    def _recv_handshake(cls, stream: BinaryIO, expected_type: int) -> bytes:
        """Receive handshake message."""
        header = stream.read(4)
        if len(header) != 4:
            raise ValueError("Connection closed during handshake")

        version, msg_type, length = header[0], header[1], struct.unpack('>H', header[2:4])[0]

        if version != PROTOCOL_VERSION:
            raise ValueError(f"Unsupported protocol version: {version}")

        if msg_type != expected_type:
            raise ValueError(f"Unexpected message type: expected {expected_type}, got {msg_type}")

        if length > 1024:
            raise ValueError("Handshake message too large")

        data = stream.read(length)
        if len(data) != length:
            raise ValueError("Connection closed during handshake")

        return data

    @classmethod
    def _send_confirmation(cls, stream: BinaryIO, session_key: bytes, is_client: bool) -> None:
        """Send handshake confirmation."""
        label = b"client-confirm" if is_client else b"server-confirm"
        confirm = hmac.new(session_key, label, hashlib.sha256).digest()[:16]
        cls._write_frame_raw(stream, confirm)

    @classmethod
    def _verify_confirmation(cls, stream: BinaryIO, session_key: bytes, expect_client: bool) -> None:
        """Verify handshake confirmation."""
        received = cls._read_frame_raw(stream)
        if len(received) != 16:
            raise ValueError("Invalid confirmation")

        label = b"client-confirm" if expect_client else b"server-confirm"
        expected = hmac.new(session_key, label, hashlib.sha256).digest()[:16]

        if not hmac.compare_digest(received, expected):
            raise ValueError("Authentication failed")

    def _write_frame(self, data: bytes) -> None:
        """Write length-prefixed frame."""
        self._write_frame_raw(self._stream, data)

    def _read_frame(self) -> bytes:
        """Read length-prefixed frame."""
        return self._read_frame_raw(self._stream)

    @staticmethod
    def _write_frame_raw(stream: BinaryIO, data: bytes) -> None:
        """Write length-prefixed frame."""
        stream.write(struct.pack('>I', len(data)))
        stream.write(data)
        stream.flush()

    @staticmethod
    def _read_frame_raw(stream: BinaryIO) -> bytes:
        """Read length-prefixed frame."""
        len_buf = stream.read(4)
        if len(len_buf) != 4:
            raise ValueError("Connection closed")

        length = struct.unpack('>I', len_buf)[0]
        if length > MAX_MESSAGE_SIZE:
            raise ValueError(f"Frame too large: {length} > {MAX_MESSAGE_SIZE}")

        data = stream.read(length)
        if len(data) != length:
            raise ValueError("Connection closed during frame read")

        return data


class ShieldListener:
    """Channel listener for accepting multiple connections."""

    def __init__(self, listener, config: ChannelConfig):
        self._listener = listener
        self._config = config

    def accept(self) -> ShieldChannel:
        """Accept next connection."""
        conn, addr = self._listener.accept()
        return ShieldChannel.accept(conn.makefile('rwb'), self._config)

    @property
    def config(self) -> ChannelConfig:
        """Get configuration."""
        return self._config

    def close(self) -> None:
        """Close listener."""
        self._listener.close()
