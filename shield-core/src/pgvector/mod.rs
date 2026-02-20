//! pgvector integration for encrypted vector similarity search
//!
//! This module provides PostgreSQL pgvector integration with Shield's
//! deterministic encryption, enabling semantic similarity search over
//! encrypted AI embeddings without exposing plaintext to the database.
//!
//! # Features
//!
//! - **Deterministic Encryption**: Same vector always produces same ciphertext (required for indexing)
//! - **Similarity Search**: L2, cosine, and inner product distance metrics
//! - **HNSW/IVFFlat Indexes**: Fast approximate nearest neighbor search
//! - **Shield Integration**: Maintains EXPTIME-secure encryption
//! - **MAC Protection**: Prevents tampering with encrypted vectors
//!
//! # Example
//!
//! ```no_run
//! use shield_core::{Shield, pgvector::{PgVectorClient, PgVectorConfig, DistanceMetric}};
//! use serde_json::json;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure pgvector client
//! let config = PgVectorConfig::new("postgresql://localhost/mydb", 1536);
//! let shield = Shield::new("master_password", "pgvector.myapp");
//! let mut client = PgVectorClient::new(config, shield)?;
//!
//! // Insert encrypted vector
//! let embedding = vec![0.1, 0.2, 0.3]; // Simplified, real embeddings are 768-3072 dim
//! let metadata = json!({"text": "The quick brown fox", "category": "example"});
//! let id = client.insert(&embedding, metadata)?;
//!
//! // Search for similar vectors
//! let query = vec![0.15, 0.25, 0.35];
//! let results = client.search_similar(&query, 10, DistanceMetric::Cosine)?;
//!
//! for result in results {
//!     println!("ID: {}, Distance: {:?}", result.id, result.distance);
//!     println!("Metadata: {}", result.metadata);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Security Model
//!
//! - **Deterministic Encryption**: Required for pgvector indexing, reduces IND-CPA security
//! - **MAC Protection**: HMAC-SHA256 prevents tampering with encrypted vectors
//! - **Content-based Nonces**: Derived from vector content using SHA256
//! - **Vector Leakage**: Vector dimension and approximate distances visible to database
//! - **Metadata**: Stored as plaintext JSONB (encrypt sensitive metadata separately)
//!
//! # PostgreSQL Schema
//!
//! ```sql
//! CREATE EXTENSION IF NOT EXISTS vector;
//!
//! CREATE TABLE encrypted_embeddings (
//!     id BIGSERIAL PRIMARY KEY,
//!     encrypted_vector vector(1536) NOT NULL,
//!     nonce BYTEA NOT NULL,
//!     mac BYTEA NOT NULL,
//!     metadata JSONB,
//!     created_at TIMESTAMPTZ DEFAULT NOW()
//! );
//!
//! CREATE INDEX ON encrypted_embeddings
//! USING hnsw (encrypted_vector vector_cosine_ops)
//! WITH (m = 16, ef_construction = 64);
//! ```

pub mod client;
pub mod config;
pub mod error;
pub mod vector;

pub use client::{CollectionStats, PgVectorClient, VectorRecord};
pub use config::{DistanceMetric, IndexType, PgVectorConfig};
pub use error::{PgVectorError, Result};
pub use vector::EncryptedVector;
