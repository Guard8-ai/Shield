//! Base types and traits for confidential computing attestation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Shield;

/// Errors that can occur during attestation operations.
#[derive(Error, Debug, Clone)]
pub enum AttestationError {
    /// Attestation verification failed
    #[error("Attestation failed: {message}")]
    VerificationFailed {
        message: String,
        code: String,
    },

    /// Missing required dependency
    #[error("Missing dependency: {0}")]
    MissingDependency(String),

    /// Not running in a TEE
    #[error("Not running in TEE: {0}")]
    NotInTEE(String),

    /// Invalid attestation evidence format
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// Network or I/O error
    #[error("IO error: {0}")]
    IoError(String),

    /// Policy violation
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Key release failed
    #[error("Key release failed: {0}")]
    KeyReleaseFailed(String),
}

impl AttestationError {
    pub fn verification_failed(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self::VerificationFailed {
            message: message.into(),
            code: code.into(),
        }
    }
}

/// Supported Trusted Execution Environment types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum TEEType {
    /// AWS Nitro Enclaves
    Nitro,
    /// GCP Confidential VMs with AMD SEV-SNP
    SevSnp,
    /// Microsoft Azure Attestation
    Maa,
    /// Intel SGX
    Sgx,
    /// Unknown or unsupported TEE
    Unknown,
}

impl TEEType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Nitro => "aws_nitro",
            Self::SevSnp => "gcp_sev_snp",
            Self::Maa => "azure_maa",
            Self::Sgx => "intel_sgx",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for TEEType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result of attestation verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AttestationResult {
    /// Whether the attestation was successfully verified
    pub verified: bool,
    /// Type of TEE that produced this attestation
    pub tee_type: TEEType,
    /// Measurements extracted from the attestation (PCRs, MRENCLAVE, etc.)
    pub measurements: HashMap<String, String>,
    /// Additional claims from the attestation
    pub claims: HashMap<String, serde_json::Value>,
    /// Unix timestamp when attestation was generated
    pub timestamp: u64,
    /// Error message if verification failed
    pub error: Option<String>,
    /// Raw attestation evidence (not serialized)
    #[serde(skip)]
    pub raw_evidence: Option<Vec<u8>>,
}

impl AttestationResult {
    /// Create a successful attestation result.
    pub fn success(tee_type: TEEType) -> Self {
        Self {
            verified: true,
            tee_type,
            measurements: HashMap::new(),
            claims: HashMap::new(),
            timestamp: current_timestamp(),
            error: None,
            raw_evidence: None,
        }
    }

    /// Create a failed attestation result.
    pub fn failure(tee_type: TEEType, error: impl Into<String>) -> Self {
        Self {
            verified: false,
            tee_type,
            measurements: HashMap::new(),
            claims: HashMap::new(),
            timestamp: current_timestamp(),
            error: Some(error.into()),
            raw_evidence: None,
        }
    }

    /// Add a measurement to the result.
    pub fn with_measurement(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.measurements.insert(name.into(), value.into());
        self
    }

    /// Add a claim to the result.
    pub fn with_claim(mut self, name: impl Into<String>, value: serde_json::Value) -> Self {
        self.claims.insert(name.into(), value);
        self
    }

    /// Set the raw evidence.
    pub fn with_raw_evidence(mut self, evidence: Vec<u8>) -> Self {
        self.raw_evidence = Some(evidence);
        self
    }

    /// Set the timestamp.
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }
}

/// Trait for attestation providers.
///
/// Implement this trait to add support for new TEE types.
#[async_trait::async_trait]
pub trait AttestationProvider: Send + Sync {
    /// Return the TEE type this provider handles.
    fn tee_type(&self) -> TEEType;

    /// Verify attestation evidence.
    ///
    /// # Arguments
    /// * `evidence` - Raw attestation evidence (format depends on TEE type)
    ///
    /// # Returns
    /// * `Ok(AttestationResult)` - Verification result with measurements and claims
    /// * `Err(AttestationError)` - If verification fails
    async fn verify(&self, evidence: &[u8]) -> Result<AttestationResult, AttestationError>;

    /// Generate attestation evidence for this TEE.
    ///
    /// # Arguments
    /// * `user_data` - Optional user data to include in attestation
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Raw attestation evidence bytes
    /// * `Err(AttestationError)` - If not running in a supported TEE
    async fn generate_evidence(
        &self,
        user_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, AttestationError>;

    /// Verify that measurements match expected values.
    fn verify_measurements(
        &self,
        result: &AttestationResult,
        expected: &HashMap<String, String>,
    ) -> bool {
        for (name, expected_value) in expected {
            match result.measurements.get(name) {
                Some(actual) if actual.to_lowercase() == expected_value.to_lowercase() => continue,
                _ => return false,
            }
        }
        true
    }
}

/// Policy for releasing keys based on attestation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyReleasePolicy {
    /// Required TEE types (empty = allow all)
    pub required_tee_types: Vec<TEEType>,
    /// Required measurements (name -> expected value)
    pub required_measurements: HashMap<String, String>,
    /// Maximum age of attestation in seconds
    pub max_age_seconds: u64,
    /// Allowed claim values (claim name -> allowed values)
    pub allowed_claims: HashMap<String, Vec<String>>,
}

impl KeyReleasePolicy {
    /// Create a new policy with default settings.
    pub fn new() -> Self {
        Self {
            required_tee_types: Vec::new(),
            required_measurements: HashMap::new(),
            max_age_seconds: 300,
            allowed_claims: HashMap::new(),
        }
    }

    /// Require a specific TEE type.
    pub fn require_tee_type(mut self, tee_type: TEEType) -> Self {
        self.required_tee_types.push(tee_type);
        self
    }

    /// Require a specific measurement value.
    pub fn require_measurement(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.required_measurements.insert(name.into(), value.into());
        self
    }

    /// Set maximum attestation age.
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age_seconds = seconds;
        self
    }

    /// Evaluate if attestation result satisfies this policy.
    pub fn evaluate(&self, result: &AttestationResult) -> bool {
        if !result.verified {
            return false;
        }

        // Check TEE type
        if !self.required_tee_types.is_empty()
            && !self.required_tee_types.contains(&result.tee_type)
        {
            return false;
        }

        // Check age
        let now = current_timestamp();
        if now.saturating_sub(result.timestamp) > self.max_age_seconds {
            return false;
        }

        // Check measurements
        for (name, expected) in &self.required_measurements {
            match result.measurements.get(name) {
                Some(actual) if actual.to_lowercase() == expected.to_lowercase() => continue,
                _ => return false,
            }
        }

        // Check claims
        for (claim_name, allowed_values) in &self.allowed_claims {
            if let Some(actual) = result.claims.get(claim_name) {
                let actual_str = actual.as_str().unwrap_or("");
                if !allowed_values.iter().any(|v| v == actual_str) {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
}

/// TEE-aware key manager with attestation-gated key release.
pub struct TEEKeyManager {
    shield: Shield,
    provider: Arc<dyn AttestationProvider>,
    policy: KeyReleasePolicy,
    #[allow(dead_code)]
    cache_ttl: u64,
}

impl TEEKeyManager {
    /// Create a new key manager.
    pub fn new(
        password: &str,
        service: &str,
        provider: Arc<dyn AttestationProvider>,
    ) -> Self {
        Self {
            shield: Shield::new(password, service),
            provider,
            policy: KeyReleasePolicy::new(),
            cache_ttl: 60,
        }
    }

    /// Set the key release policy.
    pub fn with_policy(mut self, policy: KeyReleasePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Get a key after verifying attestation.
    ///
    /// # Arguments
    /// * `attestation_evidence` - Raw attestation evidence
    /// * `key_id` - Identifier for the key to retrieve
    ///
    /// # Returns
    /// * `Ok([u8; 32])` - Derived key bytes
    /// * `Err(AttestationError)` - If attestation fails or policy not satisfied
    pub async fn get_key(
        &self,
        attestation_evidence: &[u8],
        key_id: &str,
    ) -> Result<[u8; 32], AttestationError> {
        let result = self.provider.verify(attestation_evidence).await?;

        if !self.policy.evaluate(&result) {
            return Err(AttestationError::PolicyViolation(
                "Attestation does not satisfy key release policy".into(),
            ));
        }

        Ok(self.derive_key(key_id, &result))
    }

    /// Derive a key bound to the attestation result.
    fn derive_key(&self, key_id: &str, result: &AttestationResult) -> [u8; 32] {
        use ring::digest::{Context, SHA256};

        let mut ctx = Context::new(&SHA256);
        ctx.update(key_id.as_bytes());
        ctx.update(result.tee_type.as_str().as_bytes());

        // Sort measurements for deterministic output
        let mut measurements: Vec<_> = result.measurements.iter().collect();
        measurements.sort_by_key(|(k, _)| *k);
        for (k, v) in measurements {
            ctx.update(k.as_bytes());
            ctx.update(v.as_bytes());
        }

        // Mix in the master key
        ctx.update(self.shield.key());

        let digest = ctx.finish();
        let mut key = [0u8; 32];
        key.copy_from_slice(digest.as_ref());
        key
    }

    /// Encrypt data for a specific attested TEE.
    pub async fn encrypt_for_tee(
        &self,
        data: &[u8],
        attestation_evidence: &[u8],
    ) -> Result<Vec<u8>, AttestationError> {
        let key = self.get_key(attestation_evidence, "encryption").await?;
        Shield::encrypt_with_key(&key, data).map_err(|e| {
            AttestationError::IoError(format!("Encryption failed: {e}"))
        })
    }

    /// Decrypt data inside an attested TEE.
    pub async fn decrypt_in_tee(
        &self,
        encrypted: &[u8],
        attestation_evidence: &[u8],
    ) -> Result<Vec<u8>, AttestationError> {
        let key = self.get_key(attestation_evidence, "encryption").await?;
        Shield::decrypt_with_key(&key, encrypted).map_err(|e| {
            AttestationError::IoError(format!("Decryption failed: {e}"))
        })
    }
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tee_type_display() {
        assert_eq!(TEEType::Nitro.as_str(), "aws_nitro");
        assert_eq!(TEEType::SevSnp.as_str(), "gcp_sev_snp");
        assert_eq!(TEEType::Maa.as_str(), "azure_maa");
        assert_eq!(TEEType::Sgx.as_str(), "intel_sgx");
    }

    #[test]
    fn test_attestation_result() {
        let result = AttestationResult::success(TEEType::Nitro)
            .with_measurement("PCR0", "abc123")
            .with_claim("instance_id", serde_json::json!("i-123"));

        assert!(result.verified);
        assert_eq!(result.tee_type, TEEType::Nitro);
        assert_eq!(result.measurements.get("PCR0"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_key_release_policy() {
        let policy = KeyReleasePolicy::new()
            .require_tee_type(TEEType::Nitro)
            .require_measurement("PCR0", "abc123")
            .with_max_age(300);

        let mut result = AttestationResult::success(TEEType::Nitro)
            .with_measurement("PCR0", "abc123");
        result.timestamp = current_timestamp();

        assert!(policy.evaluate(&result));

        // Wrong TEE type
        let wrong_tee = AttestationResult::success(TEEType::Sgx)
            .with_measurement("PCR0", "abc123");
        assert!(!policy.evaluate(&wrong_tee));

        // Wrong measurement
        let wrong_pcr = AttestationResult::success(TEEType::Nitro)
            .with_measurement("PCR0", "wrong");
        assert!(!policy.evaluate(&wrong_pcr));
    }
}
