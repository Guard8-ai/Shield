//! Error types for Shield operations.

use thiserror::Error;

/// Result type for Shield operations.
pub type Result<T> = std::result::Result<T, ShieldError>;

/// Errors that can occur during Shield operations.
#[derive(Error, Debug)]
pub enum ShieldError {
    /// Ciphertext is too short to contain required components.
    #[error("ciphertext too short: expected at least {expected} bytes, got {actual}")]
    CiphertextTooShort { expected: usize, actual: usize },

    /// MAC verification failed - data may be tampered or wrong key.
    #[error("authentication failed: MAC verification failed")]
    AuthenticationFailed,

    /// Key derivation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Invalid key length.
    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// Random number generation failed.
    #[error("random generation failed")]
    RandomFailed,

    /// Stream cipher error.
    #[error("stream cipher error: {0}")]
    StreamError(String),

    /// Ratchet session error.
    #[error("ratchet error: {0}")]
    RatchetError(String),

    /// Invalid format.
    #[error("invalid format")]
    InvalidFormat,

    /// Invalid share count.
    #[error("invalid share count: need at least 2 shares")]
    InvalidShareCount,

    /// Key version already exists.
    #[error("key version {0} already exists")]
    VersionExists(u32),

    /// Invalid key version.
    #[error("new version must be greater than current")]
    InvalidVersion,

    /// Unknown key version.
    #[error("unknown key version: {0}")]
    UnknownVersion(u32),

    /// Lamport key already used.
    #[error("Lamport key already used - generate new key pair")]
    LamportKeyUsed,

    /// User already exists.
    #[error("user {0} already exists")]
    UserExists(String),

    /// Member not found.
    #[error("member not found in group")]
    MemberNotFound,

    /// Channel/transport error.
    #[error("channel error: {0}")]
    ChannelError(String),

    /// Connection closed.
    #[error("connection closed")]
    ConnectionClosed,
}
