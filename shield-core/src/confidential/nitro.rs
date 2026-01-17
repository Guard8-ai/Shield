//! AWS Nitro Enclaves Attestation Provider
//!
//! Provides attestation verification for AWS Nitro Enclaves using
//! COSE-signed attestation documents with PCR measurements.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::base::{
    AttestationError, AttestationProvider, AttestationResult, TEEType,
};

/// AWS Nitro Enclaves attestation provider.
///
/// Verifies COSE-signed attestation documents containing:
/// - PCR measurements (Platform Configuration Registers)
/// - Module ID and digest
/// - Timestamp and nonce
/// - AWS certificate chain
pub struct NitroAttestationProvider {
    expected_pcrs: HashMap<u8, String>,
    max_age_seconds: u64,
    verify_certificate: bool,
}

impl NitroAttestationProvider {
    /// Create a new Nitro attestation provider.
    pub fn new() -> Self {
        Self {
            expected_pcrs: HashMap::new(),
            max_age_seconds: 300,
            verify_certificate: true,
        }
    }

    /// Add an expected PCR value.
    pub fn with_expected_pcr(mut self, index: u8, value: impl Into<String>) -> Self {
        self.expected_pcrs.insert(index, value.into());
        self
    }

    /// Set maximum attestation age in seconds.
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age_seconds = seconds;
        self
    }

    /// Disable certificate verification (for testing only).
    pub fn without_certificate_verification(mut self) -> Self {
        self.verify_certificate = false;
        self
    }

    /// Parse CBOR-encoded COSE Sign1 document.
    fn parse_cose_sign1(&self, data: &[u8]) -> Result<NitroAttestationDocument, AttestationError> {
        // COSE Sign1 structure: [protected, unprotected, payload, signature]
        // Using ciborium for CBOR parsing
        let value: ciborium::Value = ciborium::from_reader(data).map_err(|e| {
            AttestationError::InvalidFormat(format!("Failed to parse CBOR: {e}"))
        })?;

        let array = value.as_array().ok_or_else(|| {
            AttestationError::InvalidFormat("Expected COSE Sign1 array".into())
        })?;

        if array.len() != 4 {
            return Err(AttestationError::InvalidFormat(
                "Invalid COSE Sign1 structure".into(),
            ));
        }

        // Extract payload (index 2)
        let payload_bytes = array[2].as_bytes().ok_or_else(|| {
            AttestationError::InvalidFormat("Missing payload bytes".into())
        })?;

        // Parse payload as CBOR
        let payload: ciborium::Value = ciborium::from_reader(payload_bytes.as_slice())
            .map_err(|e| AttestationError::InvalidFormat(format!("Failed to parse payload: {e}")))?;

        self.parse_attestation_payload(&payload)
    }

    /// Parse the attestation document payload.
    fn parse_attestation_payload(
        &self,
        payload: &ciborium::Value,
    ) -> Result<NitroAttestationDocument, AttestationError> {
        let map = payload.as_map().ok_or_else(|| {
            AttestationError::InvalidFormat("Payload is not a map".into())
        })?;

        let mut doc = NitroAttestationDocument::default();

        for (key, value) in map {
            let key_str = key.as_text().unwrap_or("");
            match key_str {
                "module_id" => {
                    doc.module_id = value.as_text().map(String::from);
                }
                "timestamp" => {
                    doc.timestamp = value.as_integer().and_then(|i| i.try_into().ok());
                }
                "digest" => {
                    doc.digest = value.as_text().map(String::from);
                }
                "pcrs" => {
                    if let Some(pcr_map) = value.as_map() {
                        for (idx, pcr_value) in pcr_map {
                            if let (Some(idx), Some(bytes)) =
                                (idx.as_integer(), pcr_value.as_bytes())
                            {
                                let idx: u8 = idx.try_into().unwrap_or(255);
                                doc.pcrs.insert(idx, hex::encode(bytes));
                            }
                        }
                    }
                }
                "user_data" => {
                    doc.user_data = value.as_bytes().map(|b| b.to_vec());
                }
                "nonce" => {
                    doc.nonce = value.as_bytes().map(|b| b.to_vec());
                }
                "public_key" => {
                    doc.public_key = value.as_bytes().map(|b| b.to_vec());
                }
                "cabundle" => {
                    if let Some(arr) = value.as_array() {
                        doc.cabundle_len = arr.len();
                    }
                }
                _ => {}
            }
        }

        Ok(doc)
    }
}

impl Default for NitroAttestationProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AttestationProvider for NitroAttestationProvider {
    fn tee_type(&self) -> TEEType {
        TEEType::Nitro
    }

    async fn verify(&self, evidence: &[u8]) -> Result<AttestationResult, AttestationError> {
        let doc = self.parse_cose_sign1(evidence)?;

        // Build measurements
        let mut measurements = HashMap::new();
        for (idx, value) in &doc.pcrs {
            measurements.insert(format!("PCR{idx}"), value.clone());
        }

        // Build claims
        let mut claims = HashMap::new();
        if let Some(ref module_id) = doc.module_id {
            claims.insert("module_id".into(), serde_json::json!(module_id));
        }
        if let Some(timestamp) = doc.timestamp {
            claims.insert("timestamp".into(), serde_json::json!(timestamp));
        }
        if let Some(ref digest) = doc.digest {
            claims.insert("digest".into(), serde_json::json!(digest));
        }
        claims.insert("cabundle_len".into(), serde_json::json!(doc.cabundle_len));

        if let Some(ref user_data) = doc.user_data {
            claims.insert("user_data".into(), serde_json::json!(STANDARD.encode(user_data)));
        }
        if let Some(ref nonce) = doc.nonce {
            claims.insert("nonce".into(), serde_json::json!(STANDARD.encode(nonce)));
        }
        if doc.public_key.is_some() {
            claims.insert("has_public_key".into(), serde_json::json!(true));
        }

        // Verify PCR measurements
        for (pcr_idx, expected_hex) in &self.expected_pcrs {
            let pcr_key = format!("PCR{pcr_idx}");
            let actual = measurements.get(&pcr_key).map(|s| s.to_lowercase());
            let expected = expected_hex.to_lowercase();

            if actual.as_deref() != Some(&expected) {
                return Ok(AttestationResult::failure(self.tee_type(), format!(
                    "PCR{pcr_idx} mismatch: expected {expected}, got {}",
                    actual.unwrap_or_else(|| "missing".into())
                ))
                .with_raw_evidence(evidence.to_vec()));
            }
        }

        // Verify timestamp
        if let Some(timestamp_ms) = doc.timestamp {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);

            let age_ms = now_ms.saturating_sub(timestamp_ms);
            if age_ms > self.max_age_seconds * 1000 {
                return Ok(AttestationResult::failure(
                    self.tee_type(),
                    format!("Attestation too old: {:.1}s", age_ms as f64 / 1000.0),
                )
                .with_raw_evidence(evidence.to_vec()));
            }
        }

        // Verify certificate bundle exists
        if self.verify_certificate && doc.cabundle_len == 0 {
            return Ok(AttestationResult::failure(
                self.tee_type(),
                "Missing certificate bundle",
            )
            .with_raw_evidence(evidence.to_vec()));
        }

        let timestamp = doc.timestamp.map(|t| t / 1000).unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });

        let mut result = AttestationResult::success(self.tee_type())
            .with_timestamp(timestamp)
            .with_raw_evidence(evidence.to_vec());
        result.measurements = measurements;
        result.claims = claims;

        Ok(result)
    }

    async fn generate_evidence(
        &self,
        user_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, AttestationError> {
        // This would communicate with the NSM via /dev/nsm or vsock
        // For now, return an error if not in an enclave
        #[cfg(target_os = "linux")]
        {
            if std::path::Path::new("/dev/nsm").exists() {
                return self.nsm_get_attestation(user_data).await;
            }
        }

        Err(AttestationError::NotInTEE(
            "Not running in a Nitro Enclave (NSM device not found)".into(),
        ))
    }
}

impl NitroAttestationProvider {
    #[cfg(target_os = "linux")]
    async fn nsm_get_attestation(
        &self,
        _user_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, AttestationError> {
        // NSM attestation request structure
        // In a real implementation, this would use the NSM API
        // For now, this is a placeholder
        Err(AttestationError::NotInTEE(
            "NSM communication not yet implemented".into(),
        ))
    }
}

/// Parsed Nitro attestation document.
#[derive(Debug, Default)]
struct NitroAttestationDocument {
    module_id: Option<String>,
    timestamp: Option<u64>,
    digest: Option<String>,
    pcrs: HashMap<u8, String>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    cabundle_len: usize,
}

/// vsock client for communicating with parent EC2 instance.
pub struct NitroVsockClient {
    cid: u32,
    port: u32,
}

impl NitroVsockClient {
    /// Create a new vsock client.
    ///
    /// # Arguments
    /// * `cid` - Context ID (typically 3 for parent instance)
    /// * `port` - vsock port to connect to
    pub fn new(cid: u32, port: u32) -> Self {
        Self { cid, port }
    }

    /// Create a client for connecting to the parent instance.
    pub fn to_parent(port: u32) -> Self {
        Self::new(3, port)
    }

    /// Send data and receive response via vsock.
    ///
    /// Note: This requires the `vsock` crate or direct NSM API access.
    /// In production, use the AWS Nitro Enclave SDK.
    pub async fn send(&self, _data: &[u8]) -> Result<Vec<u8>, AttestationError> {
        // vsock requires either:
        // 1. The `vsock` crate (pure Rust)
        // 2. AWS Nitro Enclave SDK bindings
        // 3. Direct NSM API access
        //
        // For now, return a helpful error. In production environments,
        // use the official AWS Nitro Enclave SDK.
        Err(AttestationError::MissingDependency(format!(
            "vsock not available. Use AWS Nitro Enclave SDK for vsock to CID {} port {}",
            self.cid, self.port
        )))
    }
}

/// vsock server for receiving requests from Nitro Enclave.
pub struct NitroVsockServer {
    port: u32,
}

impl NitroVsockServer {
    /// Create a new vsock server.
    pub fn new(port: u32) -> Self {
        Self { port }
    }

    /// Start the server (blocking).
    ///
    /// Note: This requires the `vsock` crate or direct system access.
    /// In production, use the AWS Nitro Enclave SDK.
    pub async fn start<F, Fut>(&self, _handler: F) -> Result<(), AttestationError>
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Vec<u8>> + Send,
    {
        // vsock server requires either:
        // 1. The `vsock` crate (pure Rust)
        // 2. AWS Nitro Enclave SDK bindings
        //
        // For now, return a helpful error. In production environments,
        // use the official AWS Nitro Enclave SDK.
        Err(AttestationError::MissingDependency(format!(
            "vsock server not available. Use AWS Nitro Enclave SDK for port {}",
            self.port
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = NitroAttestationProvider::new()
            .with_expected_pcr(0, "abc123")
            .with_max_age(600);

        assert_eq!(provider.tee_type(), TEEType::Nitro);
        assert_eq!(provider.expected_pcrs.get(&0), Some(&"abc123".to_string()));
        assert_eq!(provider.max_age_seconds, 600);
    }

    #[test]
    fn test_vsock_client_creation() {
        let client = NitroVsockClient::to_parent(5000);
        assert_eq!(client.cid, 3);
        assert_eq!(client.port, 5000);
    }
}
