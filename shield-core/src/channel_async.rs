//! Async Shield Channel - Tokio-based async secure transport.
//!
//! Provides the same security as [`crate::channel::ShieldChannel`] but with async I/O.
//!
//! # Example
//!
//! ```rust,ignore
//! use shield_core::channel_async::{AsyncShieldChannel, ChannelConfig};
//! use tokio::net::TcpStream;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = ChannelConfig::new("shared-secret", "my-service");
//!
//!     // Client
//!     let stream = TcpStream::connect("127.0.0.1:8080").await?;
//!     let mut channel = AsyncShieldChannel::connect(stream, &config).await?;
//!
//!     channel.send(b"Hello!").await?;
//!     let response = channel.recv().await?;
//!
//!     Ok(())
//! }
//! ```

// Crypto block counters are intentionally u32
#![allow(clippy::cast_possible_truncation)]

use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Result, ShieldError};
use crate::exchange::PAKEExchange;
use crate::ratchet::RatchetSession;

// Re-export config from sync module
pub use crate::channel::ChannelConfig;

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
        let role = if self.is_initiator {
            "client"
        } else {
            "server"
        };
        self.local_contribution = PAKEExchange::derive(
            config.password(),
            &self.salt,
            role,
            Some(config.iterations()),
        );
    }

    fn compute_session_key(&self, config: &ChannelConfig) -> Result<[u8; 32]> {
        let remote = self
            .remote_contribution
            .ok_or_else(|| ShieldError::ChannelError("handshake incomplete".into()))?;

        // Include password-derived key in session key computation
        let base_key = PAKEExchange::combine(&[self.local_contribution, remote]);

        let password_key = PAKEExchange::derive(
            config.password(),
            &self.salt,
            "session",
            Some(config.iterations()),
        );

        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&base_key);
        combined.extend_from_slice(&password_key);

        let hash = ring::digest::digest(&ring::digest::SHA256, &combined);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_ref());
        Ok(result)
    }
}

/// Async Shield secure channel for encrypted communication.
///
/// Tokio-based async version of [`crate::channel::ShieldChannel`].
pub struct AsyncShieldChannel<S> {
    stream: S,
    session: RatchetSession,
    service: String,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncShieldChannel<S> {
    /// Connect as client (initiator).
    ///
    /// Performs async PAKE handshake and establishes encrypted channel.
    pub async fn connect(mut stream: S, config: &ChannelConfig) -> Result<Self> {
        let mut state = HandshakeState::new(true)?;

        // Step 1: Send ClientHello (salt)
        Self::send_handshake(&mut stream, HandshakeType::ClientHello, &state.salt).await?;

        // Step 2: Receive ServerHello (server's salt + contribution)
        let server_hello = Self::recv_handshake(&mut stream, HandshakeType::ServerHello).await?;
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
        Self::send_handshake(
            &mut stream,
            HandshakeType::Finished,
            &state.local_contribution,
        )
        .await?;

        // Derive session key and create ratchet
        let session_key = state.compute_session_key(config)?;
        let session = RatchetSession::new(&session_key, true);

        // Verify handshake with confirmation message
        Self::send_confirmation(&mut stream, &session_key, true).await?;
        Self::verify_confirmation(&mut stream, &session_key, false).await?;

        Ok(Self {
            stream,
            session,
            service: config.service().to_string(),
        })
    }

    /// Accept connection as server.
    ///
    /// Waits for client handshake and establishes encrypted channel.
    pub async fn accept(mut stream: S, config: &ChannelConfig) -> Result<Self> {
        let mut state = HandshakeState::new(false)?;

        // Step 1: Receive ClientHello
        let client_hello = Self::recv_handshake(&mut stream, HandshakeType::ClientHello).await?;
        if client_hello.len() != 16 {
            return Err(ShieldError::ChannelError("invalid ClientHello".into()));
        }

        // Mix client salt with server salt
        for (i, &b) in client_hello.iter().enumerate() {
            state.salt[i] ^= b;
        }

        state.derive_contribution(config);

        // Step 2: Send ServerHello
        let mut server_hello = Vec::with_capacity(48);
        server_hello.extend_from_slice(&state.salt);
        server_hello.extend_from_slice(&state.local_contribution);
        Self::send_handshake(&mut stream, HandshakeType::ServerHello, &server_hello).await?;

        // Step 3: Receive client contribution
        let client_finished = Self::recv_handshake(&mut stream, HandshakeType::Finished).await?;
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
        Self::verify_confirmation(&mut stream, &session_key, true).await?;
        Self::send_confirmation(&mut stream, &session_key, false).await?;

        Ok(Self {
            stream,
            session,
            service: config.service().to_string(),
        })
    }

    /// Send encrypted message.
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(ShieldError::ChannelError(format!(
                "message too large: {} > {}",
                data.len(),
                MAX_MESSAGE_SIZE
            )));
        }

        let encrypted = self.session.encrypt(data)?;
        Self::write_frame(&mut self.stream, &encrypted).await
    }

    /// Receive and decrypt message.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let encrypted = Self::read_frame(&mut self.stream).await?;
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

    /// Get underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }

    // --- Internal async helpers ---

    async fn send_handshake(stream: &mut S, msg_type: HandshakeType, data: &[u8]) -> Result<()> {
        let mut frame = Vec::with_capacity(1 + 1 + 2 + data.len());
        frame.push(PROTOCOL_VERSION);
        frame.push(msg_type as u8);
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);

        stream
            .write_all(&frame)
            .await
            .map_err(|e| ShieldError::ChannelError(e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| ShieldError::ChannelError(e.to_string()))?;
        Ok(())
    }

    async fn recv_handshake(stream: &mut S, expected_type: HandshakeType) -> Result<Vec<u8>> {
        let mut header = [0u8; 4];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|e| ShieldError::ChannelError(e.to_string()))?;

        if header[0] != PROTOCOL_VERSION {
            return Err(ShieldError::ChannelError(format!(
                "unsupported protocol version: {}",
                header[0]
            )));
        }

        if header[1] != expected_type as u8 {
            return Err(ShieldError::ChannelError(format!(
                "unexpected message type: expected {}, got {}",
                expected_type as u8, header[1]
            )));
        }

        let len = u16::from_be_bytes([header[2], header[3]]) as usize;
        if len > 1024 {
            return Err(ShieldError::ChannelError(
                "handshake message too large".into(),
            ));
        }

        let mut data = vec![0u8; len];
        stream
            .read_exact(&mut data)
            .await
            .map_err(|e| ShieldError::ChannelError(e.to_string()))?;

        Ok(data)
    }

    async fn send_confirmation(
        stream: &mut S,
        session_key: &[u8; 32],
        is_client: bool,
    ) -> Result<()> {
        let label = if is_client {
            b"client-confirm"
        } else {
            b"server-confirm"
        };
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, session_key);
        let confirm = hmac::sign(&hmac_key, label);

        Self::write_frame(stream, &confirm.as_ref()[..16]).await
    }

    async fn verify_confirmation(
        stream: &mut S,
        session_key: &[u8; 32],
        expect_client: bool,
    ) -> Result<()> {
        let received = Self::read_frame(stream).await?;
        if received.len() != 16 {
            return Err(ShieldError::ChannelError("invalid confirmation".into()));
        }

        let label = if expect_client {
            b"client-confirm"
        } else {
            b"server-confirm"
        };
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, session_key);
        let expected = hmac::sign(&hmac_key, label);

        if received.ct_eq(&expected.as_ref()[..16]).unwrap_u8() != 1 {
            return Err(ShieldError::AuthenticationFailed);
        }

        Ok(())
    }

    async fn write_frame(stream: &mut S, data: &[u8]) -> Result<()> {
        let len = data.len() as u32;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| ShieldError::ChannelError(e.to_string()))?;
        stream
            .write_all(data)
            .await
            .map_err(|e| ShieldError::ChannelError(e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| ShieldError::ChannelError(e.to_string()))?;
        Ok(())
    }

    async fn read_frame(stream: &mut S) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| ShieldError::ChannelError(e.to_string()))?;

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_MESSAGE_SIZE {
            return Err(ShieldError::ChannelError(format!(
                "frame too large: {len} > {MAX_MESSAGE_SIZE}"
            )));
        }

        let mut data = vec![0u8; len];
        stream
            .read_exact(&mut data)
            .await
            .map_err(|e| ShieldError::ChannelError(e.to_string()))?;

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    type DuplexChannel = AsyncShieldChannel<tokio::io::DuplexStream>;

    #[tokio::test]
    async fn test_async_channel_handshake() {
        let (client_stream, server_stream) = duplex(1024);
        let config = ChannelConfig::new("test-password", "test.service");

        let server_config = config.clone();
        let server_handle =
            tokio::spawn(async move { DuplexChannel::accept(server_stream, &server_config).await });

        let client = DuplexChannel::connect(client_stream, &config)
            .await
            .unwrap();
        let server = server_handle.await.unwrap().unwrap();

        assert_eq!(client.service(), "test.service");
        assert_eq!(server.service(), "test.service");
    }

    #[tokio::test]
    async fn test_async_channel_message_exchange() {
        let (client_stream, server_stream) = duplex(4096);
        let config = ChannelConfig::new("secret", "messaging.app");

        let server_config = config.clone();
        let server_handle = tokio::spawn(async move {
            let mut server = DuplexChannel::accept(server_stream, &server_config)
                .await
                .unwrap();
            let msg = server.recv().await.unwrap();
            server.send(b"Hello client!").await.unwrap();
            msg
        });

        let mut client = DuplexChannel::connect(client_stream, &config)
            .await
            .unwrap();
        client.send(b"Hello server!").await.unwrap();
        let response = client.recv().await.unwrap();

        let server_received = server_handle.await.unwrap();

        assert_eq!(server_received, b"Hello server!");
        assert_eq!(response, b"Hello client!");
    }

    #[tokio::test]
    async fn test_async_channel_wrong_password() {
        let (client_stream, server_stream) = duplex(1024);
        let client_config = ChannelConfig::new("password1", "service");
        let server_config = ChannelConfig::new("password2", "service");

        let server_handle =
            tokio::spawn(async move { DuplexChannel::accept(server_stream, &server_config).await });

        let client_result = DuplexChannel::connect(client_stream, &client_config).await;
        let server_result = server_handle.await.unwrap();

        // At least one side should fail authentication
        assert!(client_result.is_err() || server_result.is_err());
    }

    #[tokio::test]
    async fn test_async_empty_message() {
        let (client_stream, server_stream) = duplex(1024);
        let config = ChannelConfig::new("password", "service");

        let server_config = config.clone();
        let server_handle = tokio::spawn(async move {
            let mut server = DuplexChannel::accept(server_stream, &server_config)
                .await
                .unwrap();
            server.recv().await.unwrap()
        });

        let mut client = DuplexChannel::connect(client_stream, &config)
            .await
            .unwrap();
        client.send(b"").await.unwrap();

        let received = server_handle.await.unwrap();
        assert_eq!(received, b"");
    }

    #[tokio::test]
    async fn test_async_large_message() {
        let (client_stream, server_stream) = duplex(128 * 1024);
        let config = ChannelConfig::new("password", "service");

        // 64KB message
        let large_data: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();

        let server_config = config.clone();
        let expected_len = large_data.len();
        let server_handle = tokio::spawn(async move {
            let mut server = DuplexChannel::accept(server_stream, &server_config)
                .await
                .unwrap();
            let received = server.recv().await.unwrap();
            assert_eq!(received.len(), expected_len);
            received
        });

        let mut client = DuplexChannel::connect(client_stream, &config)
            .await
            .unwrap();
        client.send(&large_data).await.unwrap();

        let received = server_handle.await.unwrap();
        assert_eq!(received, large_data);
    }

    #[tokio::test]
    async fn test_async_bidirectional() {
        let (client_stream, server_stream) = duplex(4096);
        let config = ChannelConfig::new("password", "service");

        let server_config = config.clone();
        let server_handle = tokio::spawn(async move {
            let mut server = DuplexChannel::accept(server_stream, &server_config)
                .await
                .unwrap();

            server.send(b"Server first").await.unwrap();
            let msg = server.recv().await.unwrap();
            server.send(b"Server ack").await.unwrap();
            msg
        });

        let mut client = DuplexChannel::connect(client_stream, &config)
            .await
            .unwrap();

        let msg1 = client.recv().await.unwrap();
        assert_eq!(msg1, b"Server first");

        client.send(b"Client response").await.unwrap();

        let msg2 = client.recv().await.unwrap();
        assert_eq!(msg2, b"Server ack");

        let server_received = server_handle.await.unwrap();
        assert_eq!(server_received, b"Client response");
    }

    #[tokio::test]
    async fn test_async_multiple_messages() {
        let (client_stream, server_stream) = duplex(4096);
        let config = ChannelConfig::new("password", "service");

        let server_config = config.clone();
        let server_handle = tokio::spawn(async move {
            let mut server = DuplexChannel::accept(server_stream, &server_config)
                .await
                .unwrap();
            let mut messages = Vec::new();
            for _ in 0..5 {
                messages.push(server.recv().await.unwrap());
            }
            messages
        });

        let mut client = DuplexChannel::connect(client_stream, &config)
            .await
            .unwrap();

        for i in 0..5 {
            client
                .send(format!("Message {}", i).as_bytes())
                .await
                .unwrap();
        }

        let messages = server_handle.await.unwrap();
        assert_eq!(messages.len(), 5);
        assert_eq!(messages[0], b"Message 0");
        assert_eq!(messages[4], b"Message 4");
    }

    #[tokio::test]
    async fn test_async_counters() {
        let (client_stream, server_stream) = duplex(4096);
        let config = ChannelConfig::new("password", "service");

        let server_config = config.clone();
        let server_handle = tokio::spawn(async move {
            let mut server = DuplexChannel::accept(server_stream, &server_config)
                .await
                .unwrap();
            assert_eq!(server.messages_received(), 0);
            let _ = server.recv().await.unwrap();
            assert_eq!(server.messages_received(), 1);
            server.send(b"reply").await.unwrap();
            assert_eq!(server.messages_sent(), 1);
        });

        let mut client = DuplexChannel::connect(client_stream, &config)
            .await
            .unwrap();
        assert_eq!(client.messages_sent(), 0);

        client.send(b"hello").await.unwrap();
        assert_eq!(client.messages_sent(), 1);

        let _ = client.recv().await.unwrap();
        assert_eq!(client.messages_received(), 1);

        server_handle.await.unwrap();
    }
}
