//! FIDO2/WebAuthn error types

use thiserror::Error;

/// Errors that can occur during FIDO2 operations
#[derive(Error, Debug)]
pub enum Fido2Error {
    /// WebAuthn error
    #[error("WebAuthn error: {0}")]
    WebAuthn(String),

    /// Shield encryption error
    #[error("Shield encryption error: {0}")]
    Shield(#[from] crate::error::ShieldError),

    /// Credential not found
    #[error("Credential not found")]
    CredentialNotFound,

    /// Invalid challenge
    #[error("Invalid challenge")]
    InvalidChallenge,

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Counter decreased (replay attack)
    #[error("Counter decreased - possible replay attack")]
    CounterDecreased,

    /// User verification failed
    #[error("User verification failed")]
    UserVerificationFailed,
}

pub type Result<T> = std::result::Result<T, Fido2Error>;
