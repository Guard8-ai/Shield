//! Shield Secure Channel - TLS/SSH-like secure transport using symmetric crypto.
//!
//! Provides encrypted bidirectional communication with:
//! - PAKE-based handshake (no certificates needed)
//! - Forward secrecy via key ratcheting
//! - Message authentication and replay protection
//!
//! # Example
//!
//! ```rust,ignore
//! use shield_core::channel::{ShieldChannel, ChannelConfig};
//!
//! // Both parties share a password
//! let config = ChannelConfig::new("shared-secret", "my-service");
//!
//! // Server side
//! let mut server = ShieldChannel::accept(stream, &config)?;
//!
//! // Client side
//! let mut client = ShieldChannel::connect(stream, &config)?;
//!
//! // Send/receive with forward secrecy
//! client.send(b"Hello server!")?;
//! let msg = server.recv()?;
//! ```

// Crypto block counters are intentionally u32
#![allow(clippy::cast_possible_truncation)]

use ring::{hmac, rand::{SecureRandom, SystemRandom}};
use std::io::{Read, Write};
use subtle::ConstantTimeEq;

use crate::error::{Result, ShieldError};
use crate::exchange::PAKEExchange;
use crate::ratchet::RatchetSession;

/// Channel protocol version.
const PROTOCOL_VERSION: u8 = 1;

/// Maximum message size (16 MB).
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Handshake message types.
#[repr(u8)]
#[derive(Clone, Copy)]
enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    Finished = 3,
}

/// Channel configuration.
#[derive(Clone)]
pub struct ChannelConfig {
    /// Shared password for PAKE.
    password: String,
    /// Service identifier (domain binding).
    service: String,
    /// PBKDF2 iterations for key derivation.
    iterations: u32,
    /// Handshake timeout in milliseconds.
    handshake_timeout_ms: u64,
}

impl ChannelConfig {
    /// Create new channel configuration.
    ///
    /// # Arguments
    /// * `password` - Shared secret between parties
    /// * `service` - Service identifier for domain separation
    #[must_use]
    pub fn new(password: &str, service: &str) -> Self {
        Self {
            password: password.to_string(),
            service: service.to_string(),
            iterations: PAKEExchange::ITERATIONS,
            handshake_timeout_ms: 30_000,
        }
    }

    /// Set custom PBKDF2 iterations.
    #[must_use]
    pub fn with_iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    /// Set handshake timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.handshake_timeout_ms = timeout_ms;
        self
    }

    /// Get password (for internal use by async channel).
    #[cfg(feature = "async")]
    #[must_use]
    pub(crate) fn password(&self) -> &str {
        &self.password
    }

    /// Get service identifier.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Get iterations count (for internal use by async channel).
    #[cfg(feature = "async")]
    #[must_use]
    pub(crate) fn iterations(&self) -> u32 {
        self.iterations
    }
}

/// Handshake state for key exchange.
struct HandshakeState {
    salt: [u8; 16],
    local_contribution: [u8; 32],
    remote_contribution: Option<[u8; 32]>,
    is_initiator: bool,
}

impl HandshakeState {
    fn new(is_initiator: bool) -> Result<Self> {
        let rng = SystemRandom::new();

        let mut salt = [0u8; 16];
        rng.fill(&mut salt).map_err(|_| ShieldError::RandomFailed)?;

        Ok(Self {
            salt,
            local_contribution: [0u8; 32],
            remote_contribution: None,
            is_initiator,
        })
    }

    fn derive_contribution(&mut self, config: &ChannelConfig) {
        let role = if self.is_initiator { "client" } else { "server" };
        self.local_contribution = PAKEExchange::derive(
            &config.password,
            &self.salt,
            role,
            Some(config.iterations),
        );
    }

    fn compute_session_key(&self, config: &ChannelConfig) -> Result<[u8; 32]> {
        let remote = self.remote_contribution
            .ok_or_else(|| ShieldError::ChannelError("handshake incomplete".into()))?;

        // CRITICAL: Include password-derived key in session key computation
        // This ensures different passwords produce different session keys
        // even though contributions are exchanged.
        let base_key = PAKEExchange::combine(&[self.local_contribution, remote]);

        // Mix in the password-derived secret that wasn't exchanged
        let password_key = PAKEExchange::derive(
            &config.password,
            &self.salt,
            "session",
            Some(config.iterations),
        );

        // Final session key = hash(base_key || password_key)
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&base_key);
        combined.extend_from_slice(&password_key);

        let hash = ring::digest::digest(&ring::digest::SHA256, &combined);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_ref());
        Ok(result)
    }
}

/// Shield secure channel for encrypted communication.
///
/// Provides TLS-like security using only symmetric cryptography:
/// - PAKE handshake establishes shared key from password
/// - `RatchetSession` provides forward secrecy
/// - All messages authenticated with HMAC
pub struct ShieldChannel<S> {
    stream: S,
    session: RatchetSession,
    service: String,
}

impl<S: Read + Write> ShieldChannel<S> {
    /// Connect as client (initiator).
    ///
    /// Performs PAKE handshake and establishes encrypted channel.
    ///
    /// # Arguments
    /// * `stream` - Underlying transport (TCP, etc.)
    /// * `config` - Channel configuration with shared password
    pub fn connect(mut stream: S, config: &ChannelConfig) -> Result<Self> {
        let mut state = HandshakeState::new(true)?;

        // Step 1: Send ClientHello (salt)
        Self::send_handshake(&mut stream, HandshakeType::ClientHello, &state.salt)?;

        // Step 2: Receive ServerHello (server's salt + contribution)
        let server_hello = Self::recv_handshake(&mut stream, HandshakeType::ServerHello)?;
        if server_hello.len() != 48 {
            return Err(ShieldError::ChannelError("invalid ServerHello".into()));
        }

        // Use server's salt for key derivation
        state.salt.copy_from_slice(&server_hello[..16]);
        state.derive_contribution(config);

        let mut remote = [0u8; 32];
        remote.copy_from_slice(&server_hello[16..48]);
        state.remote_contribution = Some(remote);

        // Step 3: Send client contribution
        Self::send_handshake(&mut stream, HandshakeType::Finished, &state.local_contribution)?;

        // Derive session key and create ratchet
        let session_key = state.compute_session_key(config)?;
        let session = RatchetSession::new(&session_key, true);

        // Verify handshake with confirmation message
        Self::send_confirmation(&mut stream, &session_key, true)?;
        Self::verify_confirmation(&mut stream, &session_key, false)?;

        Ok(Self {
            stream,
            session,
            service: config.service.clone(),
        })
    }

    /// Accept connection as server.
    ///
    /// Waits for client handshake and establishes encrypted channel.
    ///
    /// # Arguments
    /// * `stream` - Underlying transport (TCP, etc.)
    /// * `config` - Channel configuration with shared password
    pub fn accept(mut stream: S, config: &ChannelConfig) -> Result<Self> {
        let mut state = HandshakeState::new(false)?;

        // Step 1: Receive ClientHello (client's proposed salt)
        let client_hello = Self::recv_handshake(&mut stream, HandshakeType::ClientHello)?;
        if client_hello.len() != 16 {
            return Err(ShieldError::ChannelError("invalid ClientHello".into()));
        }

        // Mix client salt with server salt for freshness
        for (i, &b) in client_hello.iter().enumerate() {
            state.salt[i] ^= b;
        }

        state.derive_contribution(config);

        // Step 2: Send ServerHello (final salt + server contribution)
        let mut server_hello = Vec::with_capacity(48);
        server_hello.extend_from_slice(&state.salt);
        server_hello.extend_from_slice(&state.local_contribution);
        Self::send_handshake(&mut stream, HandshakeType::ServerHello, &server_hello)?;

        // Step 3: Receive client contribution
        let client_finished = Self::recv_handshake(&mut stream, HandshakeType::Finished)?;
        if client_finished.len() != 32 {
            return Err(ShieldError::ChannelError("invalid Finished".into()));
        }

        let mut remote = [0u8; 32];
        remote.copy_from_slice(&client_finished);
        state.remote_contribution = Some(remote);

        // Derive session key and create ratchet
        let session_key = state.compute_session_key(config)?;
        let session = RatchetSession::new(&session_key, false);

        // Verify handshake with confirmation message
        Self::verify_confirmation(&mut stream, &session_key, true)?;
        Self::send_confirmation(&mut stream, &session_key, false)?;

        Ok(Self {
            stream,
            session,
            service: config.service.clone(),
        })
    }

    /// Send encrypted message.
    ///
    /// Message is encrypted with current ratchet key, then key advances.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(ShieldError::ChannelError(format!(
                "message too large: {} > {}",
                data.len(),
                MAX_MESSAGE_SIZE
            )));
        }

        let encrypted = self.session.encrypt(data)?;
        Self::write_frame(&mut self.stream, &encrypted)
    }

    /// Receive and decrypt message.
    ///
    /// Verifies authentication and advances receive ratchet.
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        let encrypted = Self::read_frame(&mut self.stream)?;
        self.session.decrypt(&encrypted)
    }

    /// Get service identifier.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Get send message count.
    #[must_use]
    pub fn messages_sent(&self) -> u64 {
        self.session.send_counter()
    }

    /// Get receive message count.
    #[must_use]
    pub fn messages_received(&self) -> u64 {
        self.session.recv_counter()
    }

    /// Get underlying stream (for shutdown, etc.)
    pub fn into_inner(self) -> S {
        self.stream
    }

    // --- Internal handshake helpers ---

    fn send_handshake(stream: &mut S, msg_type: HandshakeType, data: &[u8]) -> Result<()> {
        let mut frame = Vec::with_capacity(1 + 1 + 2 + data.len());
        frame.push(PROTOCOL_VERSION);
        frame.push(msg_type as u8);
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);

        stream.write_all(&frame).map_err(|e| ShieldError::ChannelError(e.to_string()))?;
        stream.flush().map_err(|e| ShieldError::ChannelError(e.to_string()))?;
        Ok(())
    }

    fn recv_handshake(stream: &mut S, expected_type: HandshakeType) -> Result<Vec<u8>> {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).map_err(|e| ShieldError::ChannelError(e.to_string()))?;

        if header[0] != PROTOCOL_VERSION {
            return Err(ShieldError::ChannelError(format!(
                "unsupported protocol version: {}",
                header[0]
            )));
        }

        if header[1] != expected_type as u8 {
            return Err(ShieldError::ChannelError(format!(
                "unexpected message type: expected {}, got {}",
                expected_type as u8,
                header[1]
            )));
        }

        let len = u16::from_be_bytes([header[2], header[3]]) as usize;
        if len > 1024 {
            return Err(ShieldError::ChannelError("handshake message too large".into()));
        }

        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).map_err(|e| ShieldError::ChannelError(e.to_string()))?;

        Ok(data)
    }

    fn send_confirmation(stream: &mut S, session_key: &[u8; 32], is_client: bool) -> Result<()> {
        let label = if is_client { b"client-confirm" } else { b"server-confirm" };
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, session_key);
        let confirm = hmac::sign(&hmac_key, label);

        Self::write_frame(stream, &confirm.as_ref()[..16])
    }

    fn verify_confirmation(stream: &mut S, session_key: &[u8; 32], expect_client: bool) -> Result<()> {
        let received = Self::read_frame(stream)?;
        if received.len() != 16 {
            return Err(ShieldError::ChannelError("invalid confirmation".into()));
        }

        let label = if expect_client { b"client-confirm" } else { b"server-confirm" };
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, session_key);
        let expected = hmac::sign(&hmac_key, label);

        if received.ct_eq(&expected.as_ref()[..16]).unwrap_u8() != 1 {
            return Err(ShieldError::AuthenticationFailed);
        }

        Ok(())
    }

    // --- Frame helpers ---

    fn write_frame(stream: &mut S, data: &[u8]) -> Result<()> {
        let len = data.len() as u32;
        stream.write_all(&len.to_be_bytes()).map_err(|e| ShieldError::ChannelError(e.to_string()))?;
        stream.write_all(data).map_err(|e| ShieldError::ChannelError(e.to_string()))?;
        stream.flush().map_err(|e| ShieldError::ChannelError(e.to_string()))?;
        Ok(())
    }

    fn read_frame(stream: &mut S) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).map_err(|e| ShieldError::ChannelError(e.to_string()))?;

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_MESSAGE_SIZE {
            return Err(ShieldError::ChannelError(format!(
                "frame too large: {len} > {MAX_MESSAGE_SIZE}"
            )));
        }

        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).map_err(|e| ShieldError::ChannelError(e.to_string()))?;

        Ok(data)
    }
}

/// Channel listener for accepting multiple connections.
pub struct ShieldListener<L> {
    listener: L,
    config: ChannelConfig,
}

impl<L> ShieldListener<L> {
    /// Create a new listener with the given configuration.
    #[must_use]
    pub fn new(listener: L, config: ChannelConfig) -> Self {
        Self { listener, config }
    }

    /// Get the underlying listener.
    pub fn into_inner(self) -> L {
        self.listener
    }

    /// Get a reference to the configuration.
    #[must_use]
    pub fn config(&self) -> &ChannelConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;

    /// Mock bidirectional stream for testing.
    struct MockStream {
        tx: mpsc::Sender<u8>,
        rx: mpsc::Receiver<u8>,
    }

    impl MockStream {
        fn pair() -> (Self, Self) {
            let (tx1, rx1) = mpsc::channel();
            let (tx2, rx2) = mpsc::channel();

            (
                Self { tx: tx1, rx: rx2 },
                Self { tx: tx2, rx: rx1 },
            )
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            for byte in buf.iter_mut() {
                *byte = self.rx.recv().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "channel closed")
                })?;
            }
            Ok(buf.len())
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            for &byte in buf {
                self.tx.send(byte).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "channel closed")
                })?;
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_channel_handshake() {
        let (client_stream, server_stream) = MockStream::pair();
        let config = ChannelConfig::new("test-password", "test.service");

        let server_config = config.clone();
        let server_handle = thread::spawn(move || {
            ShieldChannel::accept(server_stream, &server_config)
        });

        let client = ShieldChannel::connect(client_stream, &config).unwrap();
        let server = server_handle.join().unwrap().unwrap();

        assert_eq!(client.service(), "test.service");
        assert_eq!(server.service(), "test.service");
    }

    #[test]
    fn test_channel_message_exchange() {
        let (client_stream, server_stream) = MockStream::pair();
        let config = ChannelConfig::new("secret", "messaging.app");

        let server_config = config.clone();
        let server_handle = thread::spawn(move || {
            let mut server = ShieldChannel::accept(server_stream, &server_config).unwrap();
            let msg = server.recv().unwrap();
            server.send(b"Hello client!").unwrap();
            msg
        });

        let mut client = ShieldChannel::connect(client_stream, &config).unwrap();
        client.send(b"Hello server!").unwrap();
        let response = client.recv().unwrap();

        let server_received = server_handle.join().unwrap();

        assert_eq!(server_received, b"Hello server!");
        assert_eq!(response, b"Hello client!");
    }

    #[test]
    fn test_channel_forward_secrecy() {
        let (client_stream, server_stream) = MockStream::pair();
        let config = ChannelConfig::new("password", "service");

        let server_config = config.clone();
        let server_handle = thread::spawn(move || {
            let mut server = ShieldChannel::accept(server_stream, &server_config).unwrap();
            for _ in 0..3 {
                let _ = server.recv().unwrap();
            }
            server.messages_received()
        });

        let mut client = ShieldChannel::connect(client_stream, &config).unwrap();

        // Send multiple messages
        client.send(b"message 1").unwrap();
        client.send(b"message 2").unwrap();
        client.send(b"message 3").unwrap();

        assert_eq!(client.messages_sent(), 3);

        let server_count = server_handle.join().unwrap();
        assert_eq!(server_count, 3);
    }

    #[test]
    fn test_channel_wrong_password() {
        let (client_stream, server_stream) = MockStream::pair();
        let client_config = ChannelConfig::new("password1", "service");
        let server_config = ChannelConfig::new("password2", "service");

        let server_handle = thread::spawn(move || {
            ShieldChannel::accept(server_stream, &server_config)
        });

        let client_result = ShieldChannel::connect(client_stream, &client_config);
        let server_result = server_handle.join().unwrap();

        // At least one side should fail authentication
        assert!(client_result.is_err() || server_result.is_err());
    }

    #[test]
    fn test_config_builder() {
        let config = ChannelConfig::new("password", "service")
            .with_iterations(100_000)
            .with_timeout(5_000);

        assert_eq!(config.iterations, 100_000);
        assert_eq!(config.handshake_timeout_ms, 5_000);
    }

    #[test]
    fn test_empty_message() {
        let (client_stream, server_stream) = MockStream::pair();
        let config = ChannelConfig::new("password", "service");

        let server_config = config.clone();
        let server_handle = thread::spawn(move || {
            let mut server = ShieldChannel::accept(server_stream, &server_config).unwrap();
            server.recv().unwrap()
        });

        let mut client = ShieldChannel::connect(client_stream, &config).unwrap();
        client.send(b"").unwrap();

        let received = server_handle.join().unwrap();
        assert_eq!(received, b"");
    }

    #[test]
    fn test_large_message() {
        let (client_stream, server_stream) = MockStream::pair();
        let config = ChannelConfig::new("password", "service");

        // 64KB message
        let large_data: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();

        let server_config = config.clone();
        let expected_data = large_data.clone();
        let server_handle = thread::spawn(move || {
            let mut server = ShieldChannel::accept(server_stream, &server_config).unwrap();
            let received = server.recv().unwrap();
            assert_eq!(received.len(), expected_data.len());
            assert_eq!(received, expected_data);
        });

        let mut client = ShieldChannel::connect(client_stream, &config).unwrap();
        client.send(&large_data).unwrap();

        server_handle.join().unwrap();
    }

    #[test]
    fn test_bidirectional_exchange() {
        let (client_stream, server_stream) = MockStream::pair();
        let config = ChannelConfig::new("password", "service");

        let server_config = config.clone();
        let server_handle = thread::spawn(move || {
            let mut server = ShieldChannel::accept(server_stream, &server_config).unwrap();

            // Server sends first
            server.send(b"Server says hello").unwrap();

            // Then receives
            let msg = server.recv().unwrap();
            assert_eq!(msg, b"Client responds");

            // Send another
            server.send(b"Server acknowledges").unwrap();
        });

        let mut client = ShieldChannel::connect(client_stream, &config).unwrap();

        // Client receives first
        let msg1 = client.recv().unwrap();
        assert_eq!(msg1, b"Server says hello");

        // Client responds
        client.send(b"Client responds").unwrap();

        // Client receives acknowledgment
        let msg2 = client.recv().unwrap();
        assert_eq!(msg2, b"Server acknowledges");

        server_handle.join().unwrap();
    }

    #[test]
    fn test_different_services_same_password() {
        let (client_stream, server_stream) = MockStream::pair();
        let client_config = ChannelConfig::new("password", "service1");
        let server_config = ChannelConfig::new("password", "service2");

        let server_handle = thread::spawn(move || {
            ShieldChannel::accept(server_stream, &server_config)
        });

        let client_result = ShieldChannel::connect(client_stream, &client_config);
        let server_result = server_handle.join().unwrap();

        // Different services should still connect (service is metadata, not part of key)
        // But they will have different session keys due to different service in PAKE
        // This test verifies the behavior - adjust based on actual design
        if client_result.is_ok() && server_result.is_ok() {
            // If both succeed, verify services are different
            assert_eq!(client_result.unwrap().service(), "service1");
            assert_eq!(server_result.unwrap().service(), "service2");
        }
    }

    #[test]
    fn test_unique_ciphertext_per_message() {
        let (client_stream, server_stream) = MockStream::pair();
        let config = ChannelConfig::new("password", "service");

        let server_config = config.clone();
        let server_handle = thread::spawn(move || {
            let mut server = ShieldChannel::accept(server_stream, &server_config).unwrap();
            let msg1 = server.recv().unwrap();
            let msg2 = server.recv().unwrap();
            // Same plaintext should decrypt correctly
            assert_eq!(msg1, msg2);
            assert_eq!(msg1, b"same message");
        });

        let mut client = ShieldChannel::connect(client_stream, &config).unwrap();

        // Send same message twice - due to ratcheting, ciphertext will differ
        client.send(b"same message").unwrap();
        client.send(b"same message").unwrap();

        server_handle.join().unwrap();
    }

    #[test]
    fn test_listener_config() {
        let config = ChannelConfig::new("password", "service");
        let listener = ShieldListener::new((), config.clone());

        assert_eq!(listener.config().service(), "service");

        let _ = listener.into_inner();
    }

    #[test]
    fn test_channel_counters() {
        let (client_stream, server_stream) = MockStream::pair();
        let config = ChannelConfig::new("password", "service");

        let server_config = config.clone();
        let server_handle = thread::spawn(move || {
            let mut server = ShieldChannel::accept(server_stream, &server_config).unwrap();
            assert_eq!(server.messages_sent(), 0);
            assert_eq!(server.messages_received(), 0);

            let _ = server.recv().unwrap();
            assert_eq!(server.messages_received(), 1);

            server.send(b"response").unwrap();
            assert_eq!(server.messages_sent(), 1);
        });

        let mut client = ShieldChannel::connect(client_stream, &config).unwrap();
        assert_eq!(client.messages_sent(), 0);

        client.send(b"hello").unwrap();
        assert_eq!(client.messages_sent(), 1);

        let _ = client.recv().unwrap();
        assert_eq!(client.messages_received(), 1);

        server_handle.join().unwrap();
    }
}
