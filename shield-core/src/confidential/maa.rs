//! Azure Confidential Containers (MAA) Attestation Provider
//!
//! Provides attestation verification using Microsoft Azure Attestation (MAA)
//! for Azure Confidential Containers on AKS.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;

use super::base::{AttestationError, AttestationProvider, AttestationResult, TEEType};
use super::jwt::{report_data_matches, JwtVerifier};

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
    verifier: JwtVerifier,
}

impl MAAAttestationProvider {
    /// Create a new MAA attestation provider.
    ///
    /// By default the provider has **no trusted signing keys** and will
    /// therefore reject every token (fail-closed). Microsoft Azure Attestation
    /// signs tokens with RSA (RS256) keys published at the attestation
    /// instance's JWKS endpoint (`<uri>/certs`); load them via
    /// [`Self::with_jwks_json`] (or pin a specific key with
    /// [`Self::with_trusted_rs256_pem`]) and set the expected audience with
    /// [`Self::with_audience`] before verifying.
    pub fn new(attestation_uri: impl Into<String>) -> Self {
        Self {
            attestation_uri: attestation_uri.into(),
            expected_measurements: HashMap::new(),
            allowed_tee_types: vec!["sevsnpvm".into(), "sgx".into()],
            verifier: JwtVerifier::default(),
        }
    }

    /// Pin the expected token issuer (`iss` claim). Recommended.
    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.verifier.set_issuer(issuer);
        self
    }

    /// Set the expected token audience (`aud` claim). Required — verification
    /// fails closed until an audience is configured.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.verifier.set_audience(audience);
        self
    }

    /// Add a trusted RSA (RS256) public key in SPKI PEM form (the usual MAA
    /// signing-key format).
    ///
    /// # Errors
    /// Returns an error if the PEM cannot be parsed as an RSA public key.
    pub fn with_trusted_rs256_pem(
        mut self,
        kid: Option<&str>,
        pem: &str,
    ) -> Result<Self, AttestationError> {
        self.verifier.add_rs256_pem(kid, pem)?;
        Ok(self)
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
        self.verifier.add_es256_pem(kid, pem)?;
        Ok(self)
    }

    /// Load trusted RS256 signing keys from a JWKS JSON document (e.g. the
    /// document published at the MAA instance's `/certs` endpoint).
    ///
    /// # Errors
    /// Returns an error if the JWKS cannot be parsed or contains no usable key.
    pub fn with_jwks_json(mut self, jwks_json: &str) -> Result<Self, AttestationError> {
        let added = self.verifier.add_jwks_json(jwks_json)?;
        if added == 0 {
            return Err(AttestationError::InvalidFormat(
                "JWKS contained no usable RSA signing key".into(),
            ));
        }
        Ok(self)
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

    /// Set allowed TEE types.
    #[must_use]
    pub fn with_allowed_tee_types(mut self, types: Vec<String>) -> Self {
        self.allowed_tee_types = types;
        self
    }
}

#[async_trait::async_trait]
impl AttestationProvider for MAAAttestationProvider {
    fn tee_type(&self) -> TEEType {
        TEEType::Maa
    }

    async fn verify(
        &self,
        evidence: &[u8],
        expected_report_data: Option<&[u8]>,
    ) -> Result<AttestationResult, AttestationError> {
        let token = std::str::from_utf8(evidence)
            .map_err(|e| AttestationError::InvalidFormat(format!("Invalid token encoding: {e}")))?;

        // === Cryptographic verification (fail-closed) ===
        // Refuse to verify anything unless at least one trusted MAA signing key
        // is configured. Without a trusted key, a forged token cannot be
        // detected (the original audit's CORE-CRIT-1).
        if self.verifier.is_empty() {
            return Ok(AttestationResult::failure(
                self.tee_type(),
                "No trusted signing key configured; refusing to verify (fail-closed)",
            )
            .with_raw_evidence(evidence.to_vec()));
        }

        // Verify the JWS signature against a trusted MAA signing key and
        // validate the registered claims (exp/nbf, audience, optional issuer
        // pin). Any failure is a hard rejection.
        let payload: MaaJwtPayload = match self.verifier.verify(token) {
            Ok(p) => p,
            Err(e) => {
                return Ok(AttestationResult::failure(self.tee_type(), e)
                    .with_raw_evidence(evidence.to_vec()));
            }
        };

        // Build measurements
        let mut measurements = HashMap::new();

        // Extract SEV-SNP and SGX measurements
        for (key, value) in &payload.claims {
            if let Some(short) = key.strip_prefix("x-ms-sevsnpvm-") {
                if let Some(s) = value.as_str() {
                    measurements.insert(short.to_uppercase(), s.to_string());
                }
            } else if let Some(short) = key.strip_prefix("x-ms-sgx-") {
                if let Some(s) = value.as_str() {
                    measurements.insert(short.to_uppercase(), s.to_string());
                }
            }
        }

        // Challenge / freshness binding (anti-replay): the enclave must have
        // bound the fresh server-issued challenge into its report-data, which
        // MAA surfaces as the `x-ms-*-reportdata` claim (hex). A captured token
        // carrying a stale challenge is rejected.
        if let Some(challenge) = expected_report_data {
            let report_data = payload
                .claims
                .get("x-ms-sevsnpvm-reportdata")
                .or_else(|| payload.claims.get("x-ms-sgx-reportdata"))
                .and_then(serde_json::Value::as_str);
            if !report_data_matches(report_data, challenge) {
                return Ok(AttestationResult::failure(
                    self.tee_type(),
                    "Report-data does not match challenge (possible replay)",
                )
                .with_raw_evidence(evidence.to_vec()));
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
            && !self
                .allowed_tee_types
                .iter()
                .any(|t| t.to_lowercase() == att_type)
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
                .ok_or_else(|| {
                    AttestationError::InvalidFormat("Missing token in response".into())
                })?;

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
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
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
    ///
    /// Verifies the attestation evidence, then calls the Azure Key Vault
    /// Secure Key Release API to retrieve the key bound to the TEE identity.
    #[cfg(feature = "async")]
    pub async fn release_key(
        &self,
        key_name: &str,
        attestation_evidence: &[u8],
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

        // Get access token from Azure IMDS (Instance Metadata Service)
        let client = reqwest::Client::new();
        let token_url = "http://169.254.169.254/metadata/identity/oauth2/token";
        let token_response = client
            .get(token_url)
            .query(&[
                ("api-version", "2018-02-01"),
                ("resource", "https://vault.azure.net"),
            ])
            .header("Metadata", "true")
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| AttestationError::IoError(format!("IMDS token request failed: {e}")))?;

        if !token_response.status().is_success() {
            return Err(AttestationError::IoError(format!(
                "IMDS token service returned {}",
                token_response.status()
            )));
        }

        let token_json: serde_json::Value = token_response.json().await.map_err(|e| {
            AttestationError::IoError(format!("Failed to parse token response: {e}"))
        })?;

        let access_token = token_json["access_token"].as_str().ok_or_else(|| {
            AttestationError::IoError("Missing access_token in IMDS response".into())
        })?;

        // Encode attestation as base64 for the SKR request
        let attestation_b64 =
            base64::engine::general_purpose::STANDARD.encode(attestation_evidence);

        // Call Azure Key Vault Secure Key Release API
        let release_url = format!(
            "{}/keys/{}/release?api-version=7.3",
            self.vault_url.trim_end_matches('/'),
            key_name
        );

        let release_body = serde_json::json!({
            "target": attestation_b64,
        });

        let release_response = client
            .post(&release_url)
            .bearer_auth(access_token)
            .json(&release_body)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| {
                AttestationError::IoError(format!("Key Vault release request failed: {e}"))
            })?;

        if !release_response.status().is_success() {
            return Err(AttestationError::KeyReleaseFailed(format!(
                "Key Vault returned {}",
                release_response.status()
            )));
        }

        let release_json: serde_json::Value = release_response.json().await.map_err(|e| {
            AttestationError::IoError(format!("Failed to parse release response: {e}"))
        })?;

        // Extract the released key value (base64url-encoded)
        let key_value = release_json["value"]
            .as_str()
            .ok_or_else(|| AttestationError::IoError("Missing value in release response".into()))?;

        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(key_value)
            .map_err(|e| AttestationError::IoError(format!("Failed to decode released key: {e}")))
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
    ///
    /// Generates a fresh random challenge, binds it into the attestation evidence
    /// as report-data, and requires the same challenge when releasing the key so
    /// the attestation cannot be replayed.
    #[cfg(feature = "async")]
    pub async fn get_app_key(&self, key_name: &str) -> Result<Vec<u8>, AttestationError> {
        let challenge: [u8; 32] = crate::random::random_bytes()
            .map_err(|e| AttestationError::IoError(format!("Challenge RNG failed: {e}")))?;
        let attestation = self
            .maa_provider
            .generate_evidence(Some(&challenge))
            .await?;
        self.skr
            .release_key(key_name, &attestation, Some(&challenge))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    // Throwaway ECDSA P-256 test keys (NOT used anywhere real).
    const TRUSTED_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUMsUgD2xBd9RQi29kjtKwlRwG7ve\n8DButB3cyOOuaEIF0j7y/vw5GKh/lO7HDKk0CAJQtpHuNtuvVbGoOvO66A==\n-----END PUBLIC KEY-----\n";
    const TRUSTED_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZH16YhIF4SbwinAv\nI+r50a0rWNwL+sI9APs/FUaitYuhRANCAARQyxSAPbEF31FCLb2SO0rCVHAbu97w\nMG60HdzI465oQgXSPvL+/DkYqH+U7scMqTQIAlC2ke42269Vsag687ro\n-----END PRIVATE KEY-----\n";
    const ATTACKER_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbRLd/V+YqjPGnvEH\nUxCamysl/Lav5RWDE1gmkLC18wGhRANCAAQpa2+d/YGGyn/LGNQRxSenCJNhdqo4\n7QUzoeY4qqUDj8FmcU8VbiXyS2RzsD2ld7B5cIjNrxr9lktbDIGcH+Mv\n-----END PRIVATE KEY-----\n";

    fn now_secs() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    /// Mint an MAA attestation JWT signed with the given ES256 private key.
    fn make_token(
        signing_priv_pem: &str,
        aud: &str,
        report_data: Option<&str>,
        exp_offset: i64,
    ) -> String {
        let now = now_secs();
        let mut payload = serde_json::json!({
            "aud": aud,
            "iss": "https://shared.eus.attest.azure.net",
            "iat": now,
            "exp": now + exp_offset,
            "x-ms-attestation-type": "sevsnpvm",
            "x-ms-compliance-status": "azure-compliant-cvm",
            "x-ms-sevsnpvm-measurement": "deadbeef",
        });
        if let Some(rd) = report_data {
            payload["x-ms-sevsnpvm-reportdata"] = serde_json::json!(rd);
        }
        let header = Header::new(Algorithm::ES256);
        let key = EncodingKey::from_ec_pem(signing_priv_pem.as_bytes()).unwrap();
        encode(&header, &payload, &key).unwrap()
    }

    fn trusted_provider() -> MAAAttestationProvider {
        MAAAttestationProvider::new("https://shared.eus.attest.azure.net")
            .with_audience("shield-attestation")
            .with_trusted_es256_pem(None, TRUSTED_PUB_PEM)
            .unwrap()
    }

    #[test]
    fn test_provider_creation() {
        let provider = MAAAttestationProvider::new("https://test.attest.azure.net")
            .with_allowed_tee_types(vec!["sevsnpvm".into()]);
        assert_eq!(provider.tee_type(), TEEType::Maa);
    }

    #[tokio::test]
    async fn test_genuine_token_accepted() {
        let provider = trusted_provider();
        let token = make_token(TRUSTED_PRIV_PEM, "shield-attestation", None, 3600);
        let result = provider.verify(token.as_bytes(), None).await.unwrap();
        assert!(
            result.verified,
            "genuine signed token must verify: {:?}",
            result.error
        );
    }

    #[tokio::test]
    async fn test_forged_signature_rejected() {
        // Right claims, but signed by an untrusted key.
        let provider = trusted_provider();
        let token = make_token(ATTACKER_PRIV_PEM, "shield-attestation", None, 3600);
        let result = provider.verify(token.as_bytes(), None).await.unwrap();
        assert!(
            !result.verified,
            "token signed by untrusted key must be rejected"
        );
    }

    #[tokio::test]
    async fn test_garbage_signature_rejected() {
        // The audit PoC: real header+payload with the signature replaced by junk.
        let provider = trusted_provider();
        let real = make_token(TRUSTED_PRIV_PEM, "shield-attestation", None, 3600);
        let mut parts: Vec<&str> = real.split('.').collect();
        parts[2] = "AAAA";
        let forged = parts.join(".");
        let result = provider.verify(forged.as_bytes(), None).await.unwrap();
        assert!(!result.verified, "garbage signature must be rejected");
    }

    #[tokio::test]
    async fn test_no_trusted_key_fails_closed() {
        // No configured trusted key => reject everything.
        let provider =
            MAAAttestationProvider::new("https://test").with_audience("shield-attestation");
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
        let ok = provider
            .verify(token.as_bytes(), Some(&challenge))
            .await
            .unwrap();
        assert!(ok.verified, "matching challenge must verify: {:?}", ok.error);

        // Wrong challenge: rejected (replay protection).
        let wrong = [0x22u8; 32];
        let bad = provider
            .verify(token.as_bytes(), Some(&wrong))
            .await
            .unwrap();
        assert!(!bad.verified, "mismatched challenge must be rejected");

        // Missing report-data but challenge required: rejected.
        let token_no_rd = make_token(TRUSTED_PRIV_PEM, "shield-attestation", None, 3600);
        let none = provider
            .verify(token_no_rd.as_bytes(), Some(&challenge))
            .await
            .unwrap();
        assert!(
            !none.verified,
            "missing report-data must be rejected when challenge required"
        );
    }
}
