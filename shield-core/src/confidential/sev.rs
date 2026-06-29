//! GCP Confidential VMs (AMD SEV-SNP) Attestation Provider
//!
//! Provides attestation verification for GCP Confidential VMs using
//! AMD SEV-SNP hardware attestation and vTPM measurements.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use super::base::{AttestationError, AttestationProvider, AttestationResult, TEEType};

/// A trusted issuer signing key used to verify attestation JWTs.
struct TrustedJwtKey {
    kid: Option<String>,
    alg: Algorithm,
    key: DecodingKey,
}

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
    issuer: Option<String>,
    trusted_keys: Vec<TrustedJwtKey>,
}

impl SEVAttestationProvider {
    /// Create a new SEV attestation provider.
    ///
    /// By default the provider has **no trusted signing keys** and will
    /// therefore reject every token (fail-closed). Configure at least one
    /// trusted key via [`Self::with_trusted_es256_pem`],
    /// [`Self::with_trusted_rs256_pem`], or [`Self::with_jwks_json`] before use.
    pub fn new() -> Self {
        Self {
            project_id: None,
            expected_measurements: HashMap::new(),
            allowed_zones: Vec::new(),
            audience: "shield-attestation".into(),
            issuer: None,
            trusted_keys: Vec::new(),
        }
    }

    /// Pin the expected token issuer (`iss` claim). Recommended.
    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Add a trusted ECDSA P-256 (ES256) public key in SPKI PEM form.
    ///
    /// # Errors
    /// Returns an error if the PEM cannot be parsed as an EC public key.
    pub fn with_trusted_es256_pem(
        mut self,
        kid: Option<&str>,
        pem: &str,
    ) -> Result<Self, AttestationError> {
        let key = DecodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| {
            AttestationError::InvalidFormat(format!("Invalid ES256 public key: {e}"))
        })?;
        self.trusted_keys.push(TrustedJwtKey {
            kid: kid.map(String::from),
            alg: Algorithm::ES256,
            key,
        });
        Ok(self)
    }

    /// Add a trusted RSA (RS256) public key in SPKI PEM form.
    ///
    /// # Errors
    /// Returns an error if the PEM cannot be parsed as an RSA public key.
    pub fn with_trusted_rs256_pem(
        mut self,
        kid: Option<&str>,
        pem: &str,
    ) -> Result<Self, AttestationError> {
        let key = DecodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| {
            AttestationError::InvalidFormat(format!("Invalid RS256 public key: {e}"))
        })?;
        self.trusted_keys.push(TrustedJwtKey {
            kid: kid.map(String::from),
            alg: Algorithm::RS256,
            key,
        });
        Ok(self)
    }

    /// Load trusted RS256 keys from a JWKS JSON document (e.g. Google's
    /// published certificate set). Only RSA keys are imported.
    ///
    /// # Errors
    /// Returns an error if the JWKS cannot be parsed or contains no usable key.
    pub fn with_jwks_json(mut self, jwks_json: &str) -> Result<Self, AttestationError> {
        let added = import_rsa_jwks(jwks_json, &mut self.trusted_keys)?;
        if added == 0 {
            return Err(AttestationError::InvalidFormat(
                "JWKS contained no usable RSA signing key".into(),
            ));
        }
        Ok(self)
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

    /// Verify the JWS signature of `token` against the configured trusted keys
    /// and validate the registered claims. Returns the verified payload.
    fn verify_jws(&self, token: &str) -> Result<JwtPayload, String> {
        let header = decode_header(token).map_err(|e| format!("Invalid JWT header: {e}"))?;

        // Candidate keys: when the token names a `kid`, only keys with a matching
        // (or unspecified) `kid` are considered.
        let candidates: Vec<&TrustedJwtKey> = self
            .trusted_keys
            .iter()
            .filter(|k| match (header.kid.as_ref(), k.kid.as_ref()) {
                (Some(tok_kid), Some(key_kid)) => tok_kid == key_kid,
                _ => true,
            })
            .collect();

        if candidates.is_empty() {
            return Err("No trusted key matches the token's key id".into());
        }

        let mut last_err = String::from("JWT signature verification failed");
        for k in candidates {
            // The token's declared algorithm must match the trusted key's, so an
            // attacker cannot downgrade (e.g. to `none` or HS256-over-RSA-pubkey).
            if header.alg != k.alg {
                continue;
            }
            let mut validation = Validation::new(k.alg);
            validation.validate_exp = true;
            validation.validate_nbf = true;
            validation.set_audience(&[self.audience.as_str()]);
            if let Some(ref iss) = self.issuer {
                validation.set_issuer(&[iss.as_str()]);
            }
            match decode::<JwtPayload>(token, &k.key, &validation) {
                Ok(data) => return Ok(data.claims),
                Err(e) => last_err = format!("JWT verification failed: {e}"),
            }
        }
        Err(last_err)
    }
}

/// Constant-time check that a hex-encoded TEE report-data field carries the
/// expected challenge in its leading bytes (the remainder is zero-padding).
fn report_data_matches(report_data_hex: Option<&String>, challenge: &[u8]) -> bool {
    let Some(hex_str) = report_data_hex else {
        return false;
    };
    let Ok(bytes) = hex::decode(hex_str) else {
        return false;
    };
    if bytes.len() < challenge.len() {
        return false;
    }
    bool::from(bytes[..challenge.len()].ct_eq(challenge))
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

    async fn verify(
        &self,
        evidence: &[u8],
        expected_report_data: Option<&[u8]>,
    ) -> Result<AttestationResult, AttestationError> {
        let token = std::str::from_utf8(evidence)
            .map_err(|e| AttestationError::InvalidFormat(format!("Invalid token encoding: {e}")))?;

        // === Cryptographic verification (fail-closed) ===
        // Refuse to verify anything unless at least one trusted issuer key is
        // configured. Without a trusted key, a forged token cannot be detected.
        if self.trusted_keys.is_empty() {
            return Ok(AttestationResult::failure(
                self.tee_type(),
                "No trusted signing key configured; refusing to verify (fail-closed)",
            )
            .with_raw_evidence(evidence.to_vec()));
        }

        // Verify the JWS signature against a trusted issuer key and validate the
        // registered claims (exp/nbf, audience, optional issuer pin).
        let payload = match self.verify_jws(token) {
            Ok(p) => p,
            Err(e) => {
                return Ok(AttestationResult::failure(self.tee_type(), e)
                    .with_raw_evidence(evidence.to_vec()));
            }
        };

        // Challenge / freshness binding (anti-replay): the enclave must have
        // bound the fresh server-issued challenge into its SEV-SNP report-data.
        if let Some(challenge) = expected_report_data {
            if !report_data_matches(payload.sev_snp.as_ref().and_then(|s| s.report_data.as_ref()), challenge) {
                return Ok(AttestationResult::failure(
                    self.tee_type(),
                    "Report-data does not match challenge (possible replay)",
                )
                .with_raw_evidence(evidence.to_vec()));
            }
        }

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

    async fn verify(
        &self,
        evidence: &[u8],
        expected_report_data: Option<&[u8]>,
    ) -> Result<AttestationResult, AttestationError> {
        let result = self.inner.verify(evidence, expected_report_data).await?;

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
        expected_report_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, AttestationError> {
        let result = self
            .provider
            .verify(attestation_evidence, expected_report_data)
            .await?;

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

/// Import RSA signing keys from a JWKS JSON document into `out`.
/// Returns the number of keys added.
fn import_rsa_jwks(
    jwks_json: &str,
    out: &mut Vec<TrustedJwtKey>,
) -> Result<usize, AttestationError> {
    let doc: serde_json::Value = serde_json::from_str(jwks_json)
        .map_err(|e| AttestationError::InvalidFormat(format!("Invalid JWKS JSON: {e}")))?;
    let keys = doc
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| AttestationError::InvalidFormat("JWKS missing 'keys' array".into()))?;

    let mut added = 0;
    for jwk in keys {
        // Only RSA signature keys.
        if jwk.get("kty").and_then(|v| v.as_str()) != Some("RSA") {
            continue;
        }
        if let Some(use_) = jwk.get("use").and_then(|v| v.as_str()) {
            if use_ != "sig" {
                continue;
            }
        }
        let (Some(n), Some(e)) = (
            jwk.get("n").and_then(|v| v.as_str()),
            jwk.get("e").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let key = match DecodingKey::from_rsa_components(n, e) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let kid = jwk
            .get("kid")
            .and_then(|v| v.as_str())
            .map(String::from);
        out.push(TrustedJwtKey {
            kid,
            alg: Algorithm::RS256,
            key,
        });
        added += 1;
    }
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    // Throwaway ECDSA P-256 test keys (NOT used anywhere real).
    const TRUSTED_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUMsUgD2xBd9RQi29kjtKwlRwG7ve\n8DButB3cyOOuaEIF0j7y/vw5GKh/lO7HDKk0CAJQtpHuNtuvVbGoOvO66A==\n-----END PUBLIC KEY-----\n";
    const TRUSTED_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZH16YhIF4SbwinAv\nI+r50a0rWNwL+sI9APs/FUaitYuhRANCAARQyxSAPbEF31FCLb2SO0rCVHAbu97w\nMG60HdzI465oQgXSPvL+/DkYqH+U7scMqTQIAlC2ke42269Vsag687ro\n-----END PRIVATE KEY-----\n";
    const ATTACKER_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbRLd/V+YqjPGnvEH\nUxCamysl/Lav5RWDE1gmkLC18wGhRANCAAQpa2+d/YGGyn/LGNQRxSenCJNhdqo4\n7QUzoeY4qqUDj8FmcU8VbiXyS2RzsD2ld7B5cIjNrxr9lktbDIGcH+Mv\n-----END PRIVATE KEY-----\n";

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Mint a SEV attestation JWT signed with the given private key.
    fn make_token(
        signing_priv_pem: &str,
        aud: &str,
        report_data: Option<&str>,
        exp_offset: i64,
    ) -> String {
        let now = now_secs();
        let payload = serde_json::json!({
            "aud": aud,
            "iss": "https://test-issuer",
            "iat": now,
            "exp": now + exp_offset,
            "google": { "project_id": "victim", "confidential_vm": true },
            "sev_snp": { "measurement": "deadbeef", "report_data": report_data },
        });
        let header = Header::new(Algorithm::ES256);
        let key = EncodingKey::from_ec_pem(signing_priv_pem.as_bytes()).unwrap();
        encode(&header, &payload, &key).unwrap()
    }

    fn trusted_provider() -> SEVAttestationProvider {
        SEVAttestationProvider::new()
            .with_project_id("victim")
            .with_trusted_es256_pem(None, TRUSTED_PUB_PEM)
            .unwrap()
    }

    #[test]
    fn test_provider_creation() {
        let provider = SEVAttestationProvider::new()
            .with_project_id("test-project")
            .with_allowed_zones(vec!["us-central1-a".into()]);
        assert_eq!(provider.tee_type(), TEEType::SevSnp);
        assert_eq!(provider.project_id, Some("test-project".to_string()));
    }

    #[tokio::test]
    async fn test_genuine_token_accepted() {
        let provider = trusted_provider();
        let token = make_token(TRUSTED_PRIV_PEM, "shield-attestation", None, 3600);
        let result = provider.verify(token.as_bytes(), None).await.unwrap();
        assert!(result.verified, "genuine signed token must verify: {:?}", result.error);
    }

    #[tokio::test]
    async fn test_forged_signature_rejected() {
        // Token has all the right claims but is signed by an untrusted key.
        let provider = trusted_provider();
        let token = make_token(ATTACKER_PRIV_PEM, "shield-attestation", None, 3600);
        let result = provider.verify(token.as_bytes(), None).await.unwrap();
        assert!(!result.verified, "token signed by untrusted key must be rejected");
    }

    #[tokio::test]
    async fn test_garbage_signature_rejected() {
        // The audit PoC: real-looking header+payload with a junk signature.
        let provider = trusted_provider();
        let real = make_token(TRUSTED_PRIV_PEM, "shield-attestation", None, 3600);
        let mut parts: Vec<&str> = real.split('.').collect();
        parts[2] = "AAAA"; // replace signature with garbage
        let forged = parts.join(".");
        let result = provider.verify(forged.as_bytes(), None).await.unwrap();
        assert!(!result.verified, "garbage signature must be rejected");
    }

    #[tokio::test]
    async fn test_no_trusted_key_fails_closed() {
        // A provider with no configured trusted key must reject everything.
        let provider = SEVAttestationProvider::new().with_project_id("victim");
        let token = make_token(TRUSTED_PRIV_PEM, "shield-attestation", None, 3600);
        let result = provider.verify(token.as_bytes(), None).await.unwrap();
        assert!(!result.verified, "must fail closed with no trusted key");
    }

    #[tokio::test]
    async fn test_wrong_audience_rejected() {
        let provider = trusted_provider();
        let token = make_token(TRUSTED_PRIV_PEM, "attacker-audience", None, 3600);
        let result = provider.verify(token.as_bytes(), None).await.unwrap();
        assert!(!result.verified, "wrong audience must be rejected");
    }

    #[tokio::test]
    async fn test_expired_token_rejected() {
        let provider = trusted_provider();
        let token = make_token(TRUSTED_PRIV_PEM, "shield-attestation", None, -3600);
        let result = provider.verify(token.as_bytes(), None).await.unwrap();
        assert!(!result.verified, "expired token must be rejected");
    }

    #[tokio::test]
    async fn test_challenge_binding() {
        let provider = trusted_provider();
        let challenge = [0x11u8; 32];
        // report_data = challenge bytes (hex) padded to 64 bytes.
        let mut rd = challenge.to_vec();
        rd.extend_from_slice(&[0u8; 32]);
        let rd_hex = hex::encode(&rd);
        let token = make_token(TRUSTED_PRIV_PEM, "shield-attestation", Some(&rd_hex), 3600);

        // Correct challenge: accepted.
        let ok = provider.verify(token.as_bytes(), Some(&challenge)).await.unwrap();
        assert!(ok.verified, "matching challenge must verify: {:?}", ok.error);

        // Wrong challenge: rejected (replay protection).
        let wrong = [0x22u8; 32];
        let bad = provider.verify(token.as_bytes(), Some(&wrong)).await.unwrap();
        assert!(!bad.verified, "mismatched challenge must be rejected");

        // Missing report-data but challenge required: rejected.
        let token_no_rd = make_token(TRUSTED_PRIV_PEM, "shield-attestation", None, 3600);
        let none = provider.verify(token_no_rd.as_bytes(), Some(&challenge)).await.unwrap();
        assert!(!none.verified, "missing report-data must be rejected when challenge required");
    }
}
