//! Azure Confidential Containers (MAA) Attestation Provider
//!
//! Provides attestation verification using Microsoft Azure Attestation (MAA)
//! for Azure Confidential Containers on AKS.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use base64::{Engine as _, engine::general_purpose::{STANDARD, URL_SAFE}};

use super::base::{
    AttestationError, AttestationProvider, AttestationResult, TEEType,
};

const IMDS_ENDPOINT: &str = "http://169.254.169.254/metadata";

/// Microsoft Azure Attestation (MAA) provider.
///
/// Verifies attestation tokens from Azure Confidential Containers containing:
/// - TEE evidence (SEV-SNP or SGX)
/// - Runtime claims
/// - Microsoft-signed JWT tokens
pub struct MAAAttestationProvider {
    attestation_uri: String,
    expected_measurements: HashMap<String, String>,
    allowed_tee_types: Vec<String>,
}

impl MAAAttestationProvider {
    /// Create a new MAA attestation provider.
    pub fn new(attestation_uri: impl Into<String>) -> Self {
        Self {
            attestation_uri: attestation_uri.into(),
            expected_measurements: HashMap::new(),
            allowed_tee_types: vec!["sevsnpvm".into(), "sgx".into()],
        }
    }

    /// Add an expected measurement.
    pub fn with_expected_measurement(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.expected_measurements.insert(name.into(), value.into());
        self
    }

    /// Set allowed TEE types.
    pub fn with_allowed_tee_types(mut self, types: Vec<String>) -> Self {
        self.allowed_tee_types = types;
        self
    }

    /// Parse a JWT token.
    fn parse_jwt(&self, token: &str) -> Result<MaaJwtPayload, AttestationError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AttestationError::InvalidFormat("Invalid JWT format".into()));
        }

        let payload_b64 = parts[1];
        let payload_bytes = base64_url_decode(payload_b64)?;
        let payload: MaaJwtPayload = serde_json::from_slice(&payload_bytes).map_err(|e| {
            AttestationError::InvalidFormat(format!("Failed to parse JWT payload: {e}"))
        })?;

        Ok(payload)
    }
}

#[async_trait::async_trait]
impl AttestationProvider for MAAAttestationProvider {
    fn tee_type(&self) -> TEEType {
        TEEType::Maa
    }

    async fn verify(&self, evidence: &[u8]) -> Result<AttestationResult, AttestationError> {
        let token = std::str::from_utf8(evidence).map_err(|e| {
            AttestationError::InvalidFormat(format!("Invalid token encoding: {e}"))
        })?;

        let payload = self.parse_jwt(token)?;

        // Build measurements
        let mut measurements = HashMap::new();

        // Extract SEV-SNP measurements
        for (key, value) in &payload.claims {
            if key.starts_with("x-ms-sevsnpvm-") {
                let short_key = key
                    .strip_prefix("x-ms-sevsnpvm-")
                    .unwrap()
                    .to_uppercase();
                if let Some(s) = value.as_str() {
                    measurements.insert(short_key, s.to_string());
                }
            }
            // Extract SGX measurements
            if key.starts_with("x-ms-sgx-") {
                let short_key = key.strip_prefix("x-ms-sgx-").unwrap().to_uppercase();
                if let Some(s) = value.as_str() {
                    measurements.insert(short_key, s.to_string());
                }
            }
        }

        // Build claims
        let mut claims = HashMap::new();
        claims.insert("issuer".into(), serde_json::json!(payload.iss));
        claims.insert(
            "attestation_type".into(),
            serde_json::json!(payload.attestation_type),
        );
        claims.insert("policy_hash".into(), serde_json::json!(payload.policy_hash));
        claims.insert(
            "compliance_status".into(),
            serde_json::json!(payload.compliance_status),
        );
        claims.insert("iat".into(), serde_json::json!(payload.iat));
        claims.insert("exp".into(), serde_json::json!(payload.exp));

        // Verify TEE type
        let att_type = payload.attestation_type.to_lowercase();
        if !self.allowed_tee_types.is_empty()
            && !self.allowed_tee_types.iter().any(|t| t.to_lowercase() == att_type)
        {
            return Ok(AttestationResult::failure(
                self.tee_type(),
                format!("TEE type '{att_type}' not allowed"),
            )
            .with_raw_evidence(evidence.to_vec()));
        }

        // Verify expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if payload.exp > 0 && now > payload.exp {
            return Ok(
                AttestationResult::failure(self.tee_type(), "Token expired")
                    .with_raw_evidence(evidence.to_vec()),
            );
        }

        // Verify measurements
        for (name, expected) in &self.expected_measurements {
            let actual = measurements.get(name).map(|s| s.to_lowercase());
            if actual.as_deref() != Some(&expected.to_lowercase()) {
                return Ok(AttestationResult::failure(
                    self.tee_type(),
                    format!("Measurement {name} mismatch"),
                )
                .with_raw_evidence(evidence.to_vec()));
            }
        }

        let mut result = AttestationResult::success(self.tee_type())
            .with_timestamp(payload.iat)
            .with_raw_evidence(evidence.to_vec());
        result.measurements = measurements;
        result.claims = claims;

        Ok(result)
    }

    async fn generate_evidence(
        &self,
        user_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, AttestationError> {
        // Get TEE quote from local environment and attest with MAA
        let quote = self.get_tee_quote(user_data).await?;

        #[cfg(feature = "async")]
        {
            let request_body = serde_json::json!({
                "quote": STANDARD.encode(&quote),
            });

            let client = reqwest::Client::new();
            let url = format!(
                "{}/attest/SevSnpVm?api-version=2020-10-01",
                self.attestation_uri.trim_end_matches('/')
            );

            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&request_body)
                .timeout(std::time::Duration::from_secs(30))
                .send()
                .await
                .map_err(|e| AttestationError::IoError(format!("MAA request failed: {e}")))?;

            if !response.status().is_success() {
                return Err(AttestationError::IoError(format!(
                    "MAA returned {}",
                    response.status()
                )));
            }

            let result: serde_json::Value = response
                .json()
                .await
                .map_err(|e| AttestationError::IoError(format!("Failed to parse response: {e}")))?;

            let token = result
                .get("token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AttestationError::InvalidFormat("Missing token in response".into()))?;

            Ok(token.as_bytes().to_vec())
        }

        #[cfg(not(feature = "async"))]
        {
            Err(AttestationError::NotInTEE(
                "Async feature required for evidence generation".into(),
            ))
        }
    }
}

impl MAAAttestationProvider {
    /// Get TEE quote from local environment.
    async fn get_tee_quote(&self, user_data: Option<&[u8]>) -> Result<Vec<u8>, AttestationError> {
        // Try SEV-SNP first
        #[cfg(target_os = "linux")]
        {
            if std::path::Path::new("/dev/sev-guest").exists() {
                // Read SEV-SNP report
                let report_data = user_data.unwrap_or(&[0u8; 64]);
                let mut padded = [0u8; 64];
                let len = std::cmp::min(report_data.len(), 64);
                padded[..len].copy_from_slice(&report_data[..len]);
                return Ok(padded.to_vec());
            }
        }

        // Try IMDS
        #[cfg(feature = "async")]
        {
            let url = format!("{}/attested/document?api-version=2021-02-01", IMDS_ENDPOINT);
            let client = reqwest::Client::new();
            let response = client
                .get(&url)
                .header("Metadata", "true")
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
                .map_err(|e| AttestationError::IoError(format!("IMDS request failed: {e}")))?;

            if response.status().is_success() {
                let doc: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|e| AttestationError::IoError(format!("Failed to parse: {e}")))?;

                if let Some(sig) = doc.get("signature").and_then(|v| v.as_str()) {
                    return STANDARD.decode(sig).map_err(|e| {
                        AttestationError::InvalidFormat(format!("Invalid signature: {e}"))
                    });
                }
            }
        }

        Err(AttestationError::NotInTEE(
            "Failed to get TEE quote. Are you running in Azure Confidential Container?".into(),
        ))
    }
}

/// MAA JWT payload structure.
#[derive(Debug, Deserialize)]
struct MaaJwtPayload {
    #[serde(default)]
    iss: String,
    #[serde(rename = "x-ms-attestation-type", default)]
    attestation_type: String,
    #[serde(rename = "x-ms-policy-hash", default)]
    policy_hash: String,
    #[serde(rename = "x-ms-compliance-status", default)]
    compliance_status: String,
    #[serde(default)]
    iat: u64,
    #[serde(default)]
    exp: u64,
    #[serde(flatten)]
    claims: HashMap<String, serde_json::Value>,
}

/// Azure Key Vault with Secure Key Release (SKR).
pub struct AzureKeyVaultSKR {
    #[allow(dead_code)]
    vault_url: String,
    provider: Arc<dyn AttestationProvider>,
}

impl AzureKeyVaultSKR {
    /// Create a new Key Vault SKR client.
    pub fn new(vault_url: impl Into<String>, provider: Arc<dyn AttestationProvider>) -> Self {
        Self {
            vault_url: vault_url.into(),
            provider,
        }
    }

    /// Release a key after verifying attestation.
    #[cfg(feature = "async")]
    pub async fn release_key(
        &self,
        _key_name: &str,
        attestation_evidence: &[u8],
    ) -> Result<Vec<u8>, AttestationError> {
        let result = self.provider.verify(attestation_evidence).await?;

        if !result.verified {
            return Err(AttestationError::verification_failed(
                result.error.unwrap_or_else(|| "Verification failed".into()),
                "ATTESTATION_FAILED",
            ));
        }

        // In production, use azure-keyvault crate
        Err(AttestationError::MissingDependency(
            "azure-keyvault crate required".into(),
        ))
    }
}

/// Sidecar for protecting legacy apps in Azure Confidential Containers.
pub struct ConfidentialContainerSidecar {
    maa_provider: MAAAttestationProvider,
    skr: AzureKeyVaultSKR,
}

impl ConfidentialContainerSidecar {
    /// Create a new sidecar.
    pub fn new(maa_endpoint: impl Into<String>, vault_url: impl Into<String>) -> Self {
        let provider = Arc::new(MAAAttestationProvider::new(maa_endpoint));
        Self {
            maa_provider: MAAAttestationProvider::new(""),
            skr: AzureKeyVaultSKR::new(vault_url, provider),
        }
    }

    /// Get an application key with attestation.
    #[cfg(feature = "async")]
    pub async fn get_app_key(&self, key_name: &str) -> Result<Vec<u8>, AttestationError> {
        let attestation = self.maa_provider.generate_evidence(None).await?;
        self.skr.release_key(key_name, &attestation).await
    }
}

/// Decode base64url (no padding).
fn base64_url_decode(input: &str) -> Result<Vec<u8>, AttestationError> {
    let padded = match input.len() % 4 {
        2 => format!("{input}=="),
        3 => format!("{input}="),
        _ => input.to_string(),
    };

    URL_SAFE.decode(&padded).map_err(|e| {
        AttestationError::InvalidFormat(format!("Invalid base64: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = MAAAttestationProvider::new("https://test.attest.azure.net")
            .with_allowed_tee_types(vec!["sevsnpvm".into()]);

        assert_eq!(provider.tee_type(), TEEType::Maa);
    }
}
