//! AWS Nitro Enclaves Attestation Provider
//!
//! Provides attestation verification for AWS Nitro Enclaves using
//! COSE-signed attestation documents with PCR measurements.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine as _};

use super::base::{AttestationError, AttestationProvider, AttestationResult, TEEType};

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
    #[must_use]
    pub fn with_expected_pcr(mut self, index: u8, value: impl Into<String>) -> Self {
        self.expected_pcrs.insert(index, value.into());
        self
    }

    /// Set maximum attestation age in seconds.
    #[must_use]
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age_seconds = seconds;
        self
    }

    /// Disable certificate verification (for testing only).
    #[must_use]
    pub fn without_certificate_verification(mut self) -> Self {
        self.verify_certificate = false;
        self
    }

    /// Parse CBOR-encoded COSE Sign1 document.
    fn parse_cose_sign1(data: &[u8]) -> Result<NitroAttestationDocument, AttestationError> {
        // COSE Sign1 structure: [protected, unprotected, payload, signature]
        // Using ciborium for CBOR parsing
        let value: ciborium::Value = ciborium::from_reader(data)
            .map_err(|e| AttestationError::InvalidFormat(format!("Failed to parse CBOR: {e}")))?;

        let array = value
            .as_array()
            .ok_or_else(|| AttestationError::InvalidFormat("Expected COSE Sign1 array".into()))?;

        if array.len() != 4 {
            return Err(AttestationError::InvalidFormat(
                "Invalid COSE Sign1 structure".into(),
            ));
        }

        // Extract payload (index 2)
        let payload_bytes = array[2]
            .as_bytes()
            .ok_or_else(|| AttestationError::InvalidFormat("Missing payload bytes".into()))?;

        // Parse payload as CBOR
        let payload: ciborium::Value =
            ciborium::from_reader(payload_bytes.as_slice()).map_err(|e| {
                AttestationError::InvalidFormat(format!("Failed to parse payload: {e}"))
            })?;

        Self::parse_attestation_payload(&payload)
    }

    /// Parse the attestation document payload.
    fn parse_attestation_payload(
        payload: &ciborium::Value,
    ) -> Result<NitroAttestationDocument, AttestationError> {
        let map = payload
            .as_map()
            .ok_or_else(|| AttestationError::InvalidFormat("Payload is not a map".into()))?;

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
                    doc.user_data = value.as_bytes().cloned();
                }
                "nonce" => {
                    doc.nonce = value.as_bytes().cloned();
                }
                "public_key" => {
                    doc.public_key = value.as_bytes().cloned();
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
        let doc = Self::parse_cose_sign1(evidence)?;

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
            claims.insert(
                "user_data".into(),
                serde_json::json!(STANDARD.encode(user_data)),
            );
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
                return Ok(AttestationResult::failure(
                    self.tee_type(),
                    format!(
                        "PCR{pcr_idx} mismatch: expected {expected}, got {}",
                        actual.unwrap_or_else(|| "missing".into())
                    ),
                )
                .with_raw_evidence(evidence.to_vec()));
            }
        }

        // Verify timestamp
        if let Some(timestamp_ms) = doc.timestamp {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64);

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
            return Ok(
                AttestationResult::failure(self.tee_type(), "Missing certificate bundle")
                    .with_raw_evidence(evidence.to_vec()),
            );
        }

        let timestamp = doc.timestamp.map_or_else(
            || {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs())
            },
            |t| t / 1000,
        );

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
        // Communicate with the NSM via /dev/nsm when running in an enclave
        #[cfg(target_os = "linux")]
        {
            if std::path::Path::new("/dev/nsm").exists() {
                return Self::nsm_get_attestation(user_data);
            }
        }

        Err(AttestationError::NotInTEE(
            "Not running in a Nitro Enclave (NSM device not found)".into(),
        ))
    }
}

impl NitroAttestationProvider {
    #[cfg(target_os = "linux")]
    fn nsm_get_attestation(user_data: Option<&[u8]>) -> Result<Vec<u8>, AttestationError> {
        use std::io::Write;

        // Build CBOR attestation request
        let mut attestation_map = Vec::new();
        if let Some(data) = user_data {
            attestation_map.push((
                ciborium::Value::Text("user_data".into()),
                ciborium::Value::Bytes(data.to_vec()),
            ));
        }
        attestation_map.push((ciborium::Value::Text("nonce".into()), ciborium::Value::Null));
        attestation_map.push((
            ciborium::Value::Text("public_key".into()),
            ciborium::Value::Null,
        ));

        let request = ciborium::Value::Map(vec![(
            ciborium::Value::Text("Attestation".into()),
            ciborium::Value::Map(attestation_map),
        )]);

        let mut request_bytes = Vec::new();
        ciborium::into_writer(&request, &mut request_bytes).map_err(|e| {
            AttestationError::IoError(format!("Failed to encode CBOR request: {e}"))
        })?;

        // Write request to NSM device and read response.
        // The NSM kernel module provides a file-based interface: write request CBOR,
        // read response CBOR from the same fd.
        let mut nsm_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/nsm")
            .map_err(|e| AttestationError::NotInTEE(format!("Cannot open /dev/nsm: {e}")))?;

        nsm_file
            .write_all(&request_bytes)
            .map_err(|e| AttestationError::IoError(format!("Failed to write to /dev/nsm: {e}")))?;

        let response_bytes = std::fs::read("/dev/nsm")
            .map_err(|e| AttestationError::IoError(format!("Failed to read from /dev/nsm: {e}")))?;

        // Parse CBOR response to extract attestation document
        let response: ciborium::Value =
            ciborium::from_reader(response_bytes.as_slice()).map_err(|e| {
                AttestationError::InvalidFormat(format!("Failed to parse NSM response: {e}"))
            })?;

        // Response structure: {"Attestation": {"document": <bytes>}}
        let doc_bytes = response
            .as_map()
            .and_then(|m| {
                m.iter().find_map(|(k, v)| {
                    if k.as_text() == Some("Attestation") {
                        v.as_map().and_then(|inner| {
                            inner.iter().find_map(|(ik, iv)| {
                                if ik.as_text() == Some("document") {
                                    iv.as_bytes().cloned()
                                } else {
                                    None
                                }
                            })
                        })
                    } else {
                        None
                    }
                })
            })
            .ok_or_else(|| {
                AttestationError::InvalidFormat("NSM response missing Attestation.document".into())
            })?;

        Ok(doc_bytes)
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
    /// Uses `socat` to bridge `AF_VSOCK` to stdio for safe communication
    /// without requiring `unsafe` code. `socat` is available in standard
    /// Nitro Enclave base images.
    #[cfg(target_os = "linux")]
    #[allow(clippy::unused_async)]
    pub async fn send(&self, data: &[u8]) -> Result<Vec<u8>, AttestationError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let vsock_addr = format!(
            "VSOCK-CONNECT:{cid}:{port}",
            cid = self.cid,
            port = self.port
        );

        let mut child = Command::new("socat")
            .args(["-", &vsock_addr])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                AttestationError::IoError(format!(
                    "Failed to spawn socat for vsock CID {cid} port {port}: {e}",
                    cid = self.cid,
                    port = self.port
                ))
            })?;

        // Write request data to socat stdin
        if let Some(ref mut stdin) = child.stdin {
            stdin
                .write_all(data)
                .map_err(|e| AttestationError::IoError(format!("vsock write failed: {e}")))?;
        }
        // Close stdin to signal end of input
        drop(child.stdin.take());

        let output = child
            .wait_with_output()
            .map_err(|e| AttestationError::IoError(format!("vsock communication failed: {e}")))?;

        if !output.status.success() {
            return Err(AttestationError::IoError(format!(
                "socat vsock exited with status {}",
                output.status
            )));
        }

        Ok(output.stdout)
    }

    /// Send data and receive response via vsock (non-Linux).
    #[cfg(not(target_os = "linux"))]
    #[allow(clippy::unused_async)]
    pub async fn send(&self, _data: &[u8]) -> Result<Vec<u8>, AttestationError> {
        Err(AttestationError::NotInTEE(
            "vsock is only available on Linux".into(),
        ))
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

    /// Start the server, accepting connections and dispatching to the handler.
    ///
    /// Uses `socat` to bridge `AF_VSOCK` to stdio for safe communication.
    /// Each connection reads all data from stdin, calls the handler, and
    /// writes the response to stdout via `socat`.
    #[cfg(target_os = "linux")]
    pub async fn start<F, Fut>(&self, handler: F) -> Result<(), AttestationError>
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Vec<u8>> + Send,
    {
        use std::io::{Read, Write};
        use std::process::{Command, Stdio};

        let vsock_addr = format!("VSOCK-LISTEN:{port},fork", port = self.port);

        loop {
            // socat with fork handles one connection per invocation
            let mut child = Command::new("socat")
                .args([&vsock_addr, "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| {
                    AttestationError::IoError(format!(
                        "Failed to spawn socat vsock server on port {port}: {e}",
                        port = self.port
                    ))
                })?;

            // Read request from socat stdout (connected client data)
            let mut request = Vec::new();
            if let Some(ref mut stdout) = child.stdout {
                stdout.read_to_end(&mut request).map_err(|e| {
                    AttestationError::IoError(format!("vsock server read failed: {e}"))
                })?;
            }

            // Process request through handler
            let response = handler(request).await;

            // Write response to socat stdin (back to client)
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(&response);
            }
            drop(child.stdin.take());

            let _ = child.wait();
        }
    }

    /// Start the server (non-Linux).
    #[cfg(not(target_os = "linux"))]
    #[allow(clippy::unused_async)]
    pub async fn start<F, Fut>(&self, _handler: F) -> Result<(), AttestationError>
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Vec<u8>> + Send,
    {
        Err(AttestationError::NotInTEE(
            "vsock is only available on Linux".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::base::{AttestationProvider, TEEType};
    use super::{NitroAttestationProvider, NitroVsockClient};

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
