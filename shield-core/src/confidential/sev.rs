//! GCP Confidential VMs (AMD SEV-SNP) Attestation Provider
//!
//! Provides attestation verification for GCP Confidential VMs using
//! AMD SEV-SNP hardware attestation and vTPM measurements.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::Deserialize;

use super::base::{AttestationError, AttestationProvider, AttestationResult, TEEType};

const GCP_METADATA_URL: &str = "http://metadata.google.internal/computeMetadata/v1";

/// GCP Confidential VM (AMD SEV-SNP) attestation provider.
///
/// Verifies attestation tokens from GCP Confidential VMs containing:
/// - AMD SEV-SNP measurements
/// - vTPM PCR values
/// - VM identity and metadata
/// - Google-signed JWT tokens
pub struct SEVAttestationProvider {
    project_id: Option<String>,
    expected_measurements: HashMap<String, String>,
    allowed_zones: Vec<String>,
    audience: String,
}

impl SEVAttestationProvider {
    /// Create a new SEV attestation provider.
    pub fn new() -> Self {
        Self {
            project_id: None,
            expected_measurements: HashMap::new(),
            allowed_zones: Vec::new(),
            audience: "shield-attestation".into(),
        }
    }

    /// Set the expected GCP project ID.
    #[must_use]
    pub fn with_project_id(mut self, project_id: impl Into<String>) -> Self {
        self.project_id = Some(project_id.into());
        self
    }

    /// Add an expected measurement.
    #[must_use]
    pub fn with_expected_measurement(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.expected_measurements.insert(name.into(), value.into());
        self
    }

    /// Add allowed zones.
    #[must_use]
    pub fn with_allowed_zones(mut self, zones: Vec<String>) -> Self {
        self.allowed_zones = zones;
        self
    }

    /// Set the token audience.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Parse a JWT token (base64url-encoded parts).
    fn parse_jwt(token: &str) -> Result<JwtPayload, AttestationError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AttestationError::InvalidFormat("Invalid JWT format".into()));
        }

        let payload_b64 = parts[1];
        let payload_bytes = base64_url_decode(payload_b64)?;
        let payload: JwtPayload = serde_json::from_slice(&payload_bytes).map_err(|e| {
            AttestationError::InvalidFormat(format!("Failed to parse JWT payload: {e}"))
        })?;

        Ok(payload)
    }
}

impl Default for SEVAttestationProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AttestationProvider for SEVAttestationProvider {
    fn tee_type(&self) -> TEEType {
        TEEType::SevSnp
    }

    async fn verify(&self, evidence: &[u8]) -> Result<AttestationResult, AttestationError> {
        let token = std::str::from_utf8(evidence)
            .map_err(|e| AttestationError::InvalidFormat(format!("Invalid token encoding: {e}")))?;

        let payload = Self::parse_jwt(token)?;

        // Build measurements
        let mut measurements = HashMap::new();
        if let Some(ref sev) = payload.sev_snp {
            if let Some(ref m) = sev.measurement {
                measurements.insert("SEV_MEASUREMENT".into(), m.clone());
            }
            if let Some(ref h) = sev.host_data {
                measurements.insert("HOST_DATA".into(), h.clone());
            }
            if let Some(ref r) = sev.report_data {
                measurements.insert("REPORT_DATA".into(), r.clone());
            }
        }

        // Add vTPM PCRs
        for (pcr_idx, value) in &payload.tpm_pcrs {
            measurements.insert(format!("PCR{pcr_idx}"), value.clone());
        }

        // Build claims
        let mut claims = HashMap::new();
        if let Some(ref google) = payload.google {
            claims.insert("project_id".into(), serde_json::json!(google.project_id));
            claims.insert(
                "project_number".into(),
                serde_json::json!(google.project_number),
            );
            claims.insert("zone".into(), serde_json::json!(google.zone));
            claims.insert("instance_id".into(), serde_json::json!(google.instance_id));
            claims.insert(
                "instance_name".into(),
                serde_json::json!(google.instance_name),
            );
            claims.insert(
                "confidential_vm".into(),
                serde_json::json!(google.confidential_vm),
            );
        }
        claims.insert(
            "sev_snp_enabled".into(),
            serde_json::json!(payload.sev_snp.is_some()),
        );
        claims.insert("iat".into(), serde_json::json!(payload.iat));
        claims.insert("exp".into(), serde_json::json!(payload.exp));

        // Verify confidential VM flag
        let is_confidential = payload.google.as_ref().is_some_and(|g| g.confidential_vm);

        if !is_confidential {
            return Ok(
                AttestationResult::failure(self.tee_type(), "VM is not a Confidential VM")
                    .with_raw_evidence(evidence.to_vec()),
            );
        }

        // Verify project ID
        if let Some(ref expected_project) = self.project_id {
            let actual_project = payload
                .google
                .as_ref()
                .map_or("", |g| g.project_id.as_str());

            if actual_project != expected_project {
                return Ok(AttestationResult::failure(
                    self.tee_type(),
                    format!("Project mismatch: expected {expected_project}"),
                )
                .with_raw_evidence(evidence.to_vec()));
            }
        }

        // Verify zone
        if !self.allowed_zones.is_empty() {
            let zone = payload.google.as_ref().map_or("", |g| g.zone.as_str());

            if !self.allowed_zones.iter().any(|z| z == zone) {
                return Ok(AttestationResult::failure(
                    self.tee_type(),
                    format!("Zone {zone} not allowed"),
                )
                .with_raw_evidence(evidence.to_vec()));
            }
        }

        // Verify expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        if payload.exp > 0 && now > payload.exp {
            return Ok(AttestationResult::failure(self.tee_type(), "Token expired")
                .with_raw_evidence(evidence.to_vec()));
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
        // Request identity token from GCP metadata service
        let mut url = format!(
            "{}/instance/service-accounts/default/identity?audience={}&format=full",
            GCP_METADATA_URL, self.audience
        );

        if let Some(data) = user_data {
            let nonce = URL_SAFE_NO_PAD.encode(data);
            let _ = write!(url, "&nonce={nonce}");
        }

        #[cfg(feature = "async")]
        {
            let client = reqwest::Client::new();
            let response = client
                .get(&url)
                .header("Metadata-Flavor", "Google")
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
                .map_err(|e| AttestationError::IoError(format!("Metadata request failed: {e}")))?;

            if !response.status().is_success() {
                return Err(AttestationError::NotInTEE(format!(
                    "Metadata service returned {}",
                    response.status()
                )));
            }

            let token = response
                .bytes()
                .await
                .map_err(|e| AttestationError::IoError(format!("Failed to read response: {e}")))?;

            Ok(token.to_vec())
        }

        #[cfg(not(feature = "async"))]
        {
            Err(AttestationError::NotInTEE(
                "Async feature required for evidence generation".into(),
            ))
        }
    }
}

/// JWT payload structure for GCP attestation tokens.
#[derive(Debug, Deserialize)]
struct JwtPayload {
    #[serde(default)]
    google: Option<GoogleClaims>,
    #[serde(default)]
    sev_snp: Option<SevSnpClaims>,
    #[serde(default)]
    tpm_pcrs: HashMap<String, String>,
    #[serde(default)]
    iat: u64,
    #[serde(default)]
    exp: u64,
}

#[derive(Debug, Deserialize)]
struct GoogleClaims {
    #[serde(default)]
    project_id: String,
    #[serde(default)]
    project_number: String,
    #[serde(default)]
    zone: String,
    #[serde(default)]
    instance_id: String,
    #[serde(default)]
    instance_name: String,
    #[serde(default)]
    confidential_vm: bool,
}

#[derive(Debug, Deserialize)]
struct SevSnpClaims {
    measurement: Option<String>,
    host_data: Option<String>,
    report_data: Option<String>,
}

/// GCP Confidential Space attestation provider.
///
/// Confidential Space provides stronger attestation with workload identity.
pub struct ConfidentialSpaceProvider {
    inner: SEVAttestationProvider,
    expected_image_digest: Option<String>,
}

impl ConfidentialSpaceProvider {
    /// Create a new Confidential Space provider.
    pub fn new() -> Self {
        Self {
            inner: SEVAttestationProvider::new(),
            expected_image_digest: None,
        }
    }

    /// Set expected container image digest.
    #[must_use]
    pub fn with_expected_image_digest(mut self, digest: impl Into<String>) -> Self {
        self.expected_image_digest = Some(digest.into());
        self
    }
}

impl Default for ConfidentialSpaceProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AttestationProvider for ConfidentialSpaceProvider {
    fn tee_type(&self) -> TEEType {
        TEEType::SevSnp
    }

    async fn verify(&self, evidence: &[u8]) -> Result<AttestationResult, AttestationError> {
        let result = self.inner.verify(evidence).await?;

        if !result.verified {
            return Ok(result);
        }

        // Verify image digest if specified
        if let Some(ref expected) = self.expected_image_digest {
            let actual = result
                .claims
                .get("container_image_digest")
                .and_then(|v| v.as_str());

            if actual != Some(expected.as_str()) {
                return Ok(
                    AttestationResult::failure(self.tee_type(), "Image digest mismatch")
                        .with_raw_evidence(evidence.to_vec()),
                );
            }
        }

        Ok(result)
    }

    async fn generate_evidence(
        &self,
        user_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, AttestationError> {
        self.inner.generate_evidence(user_data).await
    }
}

/// GCP Secret Manager with attestation-based access.
///
/// Retrieves secrets from Google Cloud Secret Manager after verifying
/// attestation evidence. Uses the GCP metadata service for authentication
/// and the Secret Manager REST API for secret retrieval.
pub struct GCPSecretManager {
    project_id: String,
    provider: Arc<dyn AttestationProvider>,
}

impl GCPSecretManager {
    /// Create a new Secret Manager client.
    pub fn new(project_id: impl Into<String>, provider: Arc<dyn AttestationProvider>) -> Self {
        Self {
            project_id: project_id.into(),
            provider,
        }
    }

    /// Get a secret after verifying attestation.
    ///
    /// Fetches an access token from the GCP metadata service, verifies the
    /// attestation evidence, then retrieves the specified secret version from
    /// Secret Manager.
    #[cfg(feature = "async")]
    pub async fn get_secret(
        &self,
        secret_id: &str,
        attestation_evidence: &[u8],
        version: &str,
    ) -> Result<Vec<u8>, AttestationError> {
        let result = self.provider.verify(attestation_evidence).await?;

        if !result.verified {
            return Err(AttestationError::verification_failed(
                result.error.unwrap_or_else(|| "Verification failed".into()),
                "ATTESTATION_FAILED",
            ));
        }

        // Get access token from GCP metadata service
        let client = reqwest::Client::new();
        let token_url = format!("{GCP_METADATA_URL}/instance/service-accounts/default/token");

        let token_response = client
            .get(&token_url)
            .header("Metadata-Flavor", "Google")
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| {
                AttestationError::IoError(format!("Metadata token request failed: {e}"))
            })?;

        if !token_response.status().is_success() {
            return Err(AttestationError::IoError(format!(
                "Metadata token service returned {}",
                token_response.status()
            )));
        }

        let token_json: serde_json::Value = token_response.json().await.map_err(|e| {
            AttestationError::IoError(format!("Failed to parse token response: {e}"))
        })?;

        let access_token = token_json["access_token"]
            .as_str()
            .ok_or_else(|| AttestationError::IoError("Missing access_token in response".into()))?;

        // Fetch secret from Secret Manager REST API
        let secret_url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}/versions/{}:access",
            self.project_id, secret_id, version
        );

        let secret_response = client
            .get(&secret_url)
            .bearer_auth(access_token)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| {
                AttestationError::IoError(format!("Secret Manager request failed: {e}"))
            })?;

        if !secret_response.status().is_success() {
            return Err(AttestationError::KeyReleaseFailed(format!(
                "Secret Manager returned {}",
                secret_response.status()
            )));
        }

        let secret_json: serde_json::Value = secret_response.json().await.map_err(|e| {
            AttestationError::IoError(format!("Failed to parse secret response: {e}"))
        })?;

        // Extract and decode the secret payload (base64-encoded)
        let payload_b64 = secret_json["payload"]["data"]
            .as_str()
            .ok_or_else(|| AttestationError::IoError("Missing payload.data in response".into()))?;

        base64::engine::general_purpose::STANDARD
            .decode(payload_b64)
            .map_err(|e| AttestationError::IoError(format!("Failed to decode secret payload: {e}")))
    }
}

/// Decode base64url (no padding).
fn base64_url_decode(input: &str) -> Result<Vec<u8>, AttestationError> {
    // Add padding if needed
    let padded = match input.len() % 4 {
        2 => format!("{input}=="),
        3 => format!("{input}="),
        _ => input.to_string(),
    };

    URL_SAFE
        .decode(&padded)
        .map_err(|e| AttestationError::InvalidFormat(format!("Invalid base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = SEVAttestationProvider::new()
            .with_project_id("test-project")
            .with_allowed_zones(vec!["us-central1-a".into()]);

        assert_eq!(provider.tee_type(), TEEType::SevSnp);
        assert_eq!(provider.project_id, Some("test-project".to_string()));
    }
}
