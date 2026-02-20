//! pgvector error types

use thiserror::Error;

/// Errors that can occur during pgvector operations
#[derive(Error, Debug)]
pub enum PgVectorError {
    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// Shield encryption error
    #[error("Shield encryption error: {0}")]
    Shield(#[from] crate::error::ShieldError),

    /// Invalid vector dimension
    #[error("Invalid vector dimension: expected {expected}, got {actual}")]
    InvalidDimension { expected: usize, actual: usize },

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Vector not found
    #[error("Vector not found")]
    VectorNotFound,

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

#[cfg(feature = "pgvector")]
impl From<tokio_postgres::Error> for PgVectorError {
    fn from(err: tokio_postgres::Error) -> Self {
        Self::Database(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, PgVectorError>;
