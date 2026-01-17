//! OpenAPI/Swagger Support for Confidential Computing APIs
//!
//! Provides utoipa schemas and documentation for attestation endpoints.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Request to verify attestation evidence.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AttestationRequest {
    /// Base64-encoded attestation evidence
    #[schema(example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub attestation: String,

    /// Optional user data to bind to attestation (base64-encoded)
    #[schema(example = "bm9uY2UxMjM=")]
    pub user_data: Option<String>,

    /// Optional nonce for freshness
    #[schema(example = "YWJjMTIz")]
    pub nonce: Option<String>,
}

/// Response from attestation verification.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AttestationResponse {
    /// Whether the attestation was successfully verified
    #[schema(example = true)]
    pub verified: bool,

    /// Type of TEE that produced this attestation
    #[schema(example = "aws_nitro")]
    pub tee_type: String,

    /// Measurements extracted from the attestation (e.g., PCRs, MRENCLAVE)
    #[schema(example = json!({"PCR0": "abc123...", "PCR1": "def456..."}))]
    pub measurements: HashMap<String, String>,

    /// Additional claims from the attestation
    #[schema(example = json!({"instance_id": "i-123", "region": "us-east-1"}))]
    pub claims: HashMap<String, serde_json::Value>,

    /// Unix timestamp when attestation was generated
    #[schema(example = 1705420800)]
    pub timestamp: u64,

    /// Error message if verification failed
    #[schema(example = "PCR0 mismatch")]
    pub error: Option<String>,
}

/// Request to encrypt data with attestation binding.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EncryptRequest {
    /// Data to encrypt (base64-encoded)
    #[schema(example = "SGVsbG8gV29ybGQ=")]
    pub data: String,

    /// Attestation evidence for key derivation
    #[schema(example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub attestation: String,

    /// Optional key identifier
    #[schema(example = "encryption")]
    pub key_id: Option<String>,
}

/// Response from encryption operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EncryptResponse {
    /// Encrypted data (base64-encoded)
    #[schema(example = "CiYKEAoMCgp0ZXN0...")]
    pub encrypted: String,

    /// Key ID used for encryption
    #[schema(example = "encryption")]
    pub key_id: String,
}

/// Request to decrypt data.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DecryptRequest {
    /// Encrypted data (base64-encoded)
    #[schema(example = "CiYKEAoMCgp0ZXN0...")]
    pub encrypted: String,

    /// Attestation evidence for key derivation
    #[schema(example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub attestation: String,

    /// Key identifier
    #[schema(example = "encryption")]
    pub key_id: Option<String>,
}

/// Response from decryption operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DecryptResponse {
    /// Decrypted data (base64-encoded)
    #[schema(example = "SGVsbG8gV29ybGQ=")]
    pub decrypted: String,
}

/// Health check response with TEE status.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    /// Overall health status
    #[schema(example = "healthy")]
    pub status: String,

    /// TEE type if running in TEE
    #[schema(example = "aws_nitro")]
    pub tee_type: Option<String>,

    /// Whether running in a verified TEE
    #[schema(example = true)]
    pub in_tee: bool,

    /// Measurements from self-attestation
    #[schema(example = json!({"PCR0": "abc123..."}))]
    pub measurements: Option<HashMap<String, String>>,
}

/// Error response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    /// Error code
    #[schema(example = "ATTESTATION_FAILED")]
    pub code: String,

    /// Error message
    #[schema(example = "PCR0 mismatch: expected abc123, got def456")]
    pub message: String,

    /// Additional error details
    pub details: Option<serde_json::Value>,
}

/// OpenAPI schemas for Shield Confidential Computing.
pub struct OpenAPISchemas;

impl OpenAPISchemas {
    /// Generate OpenAPI component schemas.
    #[cfg(feature = "openapi")]
    #[allow(dead_code)]
    pub fn components() -> utoipa::openapi::Components {
        use utoipa::openapi::ComponentsBuilder;

        ComponentsBuilder::new()
            .schema_from::<AttestationRequest>()
            .schema_from::<AttestationResponse>()
            .schema_from::<EncryptRequest>()
            .schema_from::<EncryptResponse>()
            .schema_from::<DecryptRequest>()
            .schema_from::<DecryptResponse>()
            .schema_from::<HealthResponse>()
            .schema_from::<ErrorResponse>()
            .build()
    }
}

/// OpenAPI documentation for the attestation API.
#[cfg(feature = "openapi")]
#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "Shield Confidential Computing API",
        version = "1.0.0",
        description = "EXPTIME-secure encryption with hardware attestation verification",
        license(name = "CC0-1.0")
    ),
    paths(
        verify_attestation,
        get_attestation,
        encrypt_data,
        decrypt_data,
        health_check,
    ),
    components(
        schemas(
            AttestationRequest,
            AttestationResponse,
            EncryptRequest,
            EncryptResponse,
            DecryptRequest,
            DecryptResponse,
            HealthResponse,
            ErrorResponse,
        )
    ),
    tags(
        (name = "attestation", description = "TEE attestation operations"),
        (name = "encryption", description = "Attestation-bound encryption"),
        (name = "health", description = "Health and status endpoints")
    )
)]
#[allow(dead_code)]
pub struct ShieldConfidentialApi;

// OpenAPI stub functions - used by utoipa for documentation generation
#[allow(dead_code)]
mod openapi_stubs {
    #[allow(unused_imports)]
    use super::*;

    /// Verify attestation evidence.
    #[cfg(feature = "openapi")]
    #[utoipa::path(
        post,
        path = "/api/attestation/verify",
        tag = "attestation",
        request_body = AttestationRequest,
        responses(
            (status = 200, description = "Attestation verification result", body = AttestationResponse),
            (status = 400, description = "Invalid request", body = ErrorResponse),
            (status = 401, description = "Attestation failed", body = ErrorResponse),
        )
    )]
    pub async fn verify_attestation() {}

    /// Get server attestation evidence.
    #[cfg(feature = "openapi")]
    #[utoipa::path(
        get,
        path = "/api/attestation",
        tag = "attestation",
        params(
            ("user_data" = Option<String>, Query, description = "Optional user data (base64)")
        ),
        responses(
            (status = 200, description = "Server attestation evidence", body = AttestationResponse),
            (status = 503, description = "Not running in TEE", body = ErrorResponse),
        )
    )]
    pub async fn get_attestation() {}

    /// Encrypt data with attestation binding.
    #[cfg(feature = "openapi")]
    #[utoipa::path(
        post,
        path = "/api/secure/encrypt",
        tag = "encryption",
        request_body = EncryptRequest,
        responses(
            (status = 200, description = "Encrypted data", body = EncryptResponse),
            (status = 400, description = "Encryption failed", body = ErrorResponse),
            (status = 401, description = "Attestation required", body = ErrorResponse),
        ),
        security(
            ("attestation" = [])
        )
    )]
    pub async fn encrypt_data() {}

    /// Decrypt data inside TEE.
    #[cfg(feature = "openapi")]
    #[utoipa::path(
        post,
        path = "/api/secure/decrypt",
        tag = "encryption",
        request_body = DecryptRequest,
        responses(
            (status = 200, description = "Decrypted data", body = DecryptResponse),
            (status = 400, description = "Decryption failed", body = ErrorResponse),
            (status = 401, description = "Attestation required", body = ErrorResponse),
        ),
        security(
            ("attestation" = [])
        )
    )]
    pub async fn decrypt_data() {}

    /// Health check with TEE status.
    #[cfg(feature = "openapi")]
    #[utoipa::path(
        get,
        path = "/api/health",
        tag = "health",
        responses(
            (status = 200, description = "Health status", body = HealthResponse),
        )
    )]
    pub async fn health_check() {}
}

#[cfg(feature = "openapi")]
pub use openapi_stubs::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_request_serialization() {
        let req = AttestationRequest {
            attestation: "test".into(),
            user_data: Some("data".into()),
            nonce: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"attestation\":\"test\""));
    }

    #[test]
    fn test_attestation_response_serialization() {
        let mut resp = AttestationResponse {
            verified: true,
            tee_type: "aws_nitro".into(),
            measurements: HashMap::new(),
            claims: HashMap::new(),
            timestamp: 12345,
            error: None,
        };
        resp.measurements.insert("PCR0".into(), "abc".into());

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"verified\":true"));
        assert!(json.contains("\"tee_type\":\"aws_nitro\""));
    }
}
