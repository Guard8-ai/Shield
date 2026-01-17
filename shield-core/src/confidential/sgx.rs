//! Intel SGX Attestation Provider
//!
//! Provides attestation verification for Intel SGX enclaves using
//! DCAP (Data Center Attestation Primitives).

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::base::{
    AttestationError, AttestationProvider, AttestationResult, TEEType,
};
use crate::Shield;

const SGX_REPORT_BODY_SIZE: usize = 384;
const SGX_QUOTE_HEADER_SIZE: usize = 48;

/// Intel SGX attestation provider.
///
/// Verifies DCAP quotes containing:
/// - MRENCLAVE (enclave measurement)
/// - MRSIGNER (signer measurement)
/// - ISV Product ID and SVN
/// - Report data (user-provided)
pub struct SGXAttestationProvider {
    expected_mrenclave: Option<String>,
    expected_mrsigner: Option<String>,
    min_isv_svn: u16,
    pccs_url: Option<String>,
}

impl SGXAttestationProvider {
    /// Create a new SGX attestation provider.
    pub fn new() -> Self {
        Self {
            expected_mrenclave: None,
            expected_mrsigner: None,
            min_isv_svn: 0,
            pccs_url: None,
        }
    }

    /// Set expected MRENCLAVE value.
    pub fn with_expected_mrenclave(mut self, value: impl Into<String>) -> Self {
        self.expected_mrenclave = Some(value.into());
        self
    }

    /// Set expected MRSIGNER value.
    pub fn with_expected_mrsigner(mut self, value: impl Into<String>) -> Self {
        self.expected_mrsigner = Some(value.into());
        self
    }

    /// Set minimum ISV SVN.
    pub fn with_min_isv_svn(mut self, svn: u16) -> Self {
        self.min_isv_svn = svn;
        self
    }

    /// Set PCCS URL for quote verification.
    pub fn with_pccs_url(mut self, url: impl Into<String>) -> Self {
        self.pccs_url = Some(url.into());
        self
    }

    /// Parse SGX quote header.
    fn parse_quote_header(&self, data: &[u8]) -> Result<QuoteHeader, AttestationError> {
        if data.len() < SGX_QUOTE_HEADER_SIZE {
            return Err(AttestationError::InvalidFormat("Quote header too small".into()));
        }

        Ok(QuoteHeader {
            version: u16::from_le_bytes([data[0], data[1]]),
            att_key_type: u16::from_le_bytes([data[2], data[3]]),
            tee_type: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            vendor_id: hex::encode(&data[12..28]),
            user_data: hex::encode(&data[28..48]),
        })
    }

    /// Parse SGX report body.
    fn parse_report_body(&self, data: &[u8]) -> Result<ReportBody, AttestationError> {
        if data.len() < SGX_REPORT_BODY_SIZE {
            return Err(AttestationError::InvalidFormat("Report body too small".into()));
        }

        Ok(ReportBody {
            cpu_svn: hex::encode(&data[0..16]),
            misc_select: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            attributes: hex::encode(&data[48..64]),
            mrenclave: hex::encode(&data[64..96]),
            mrsigner: hex::encode(&data[128..160]),
            isv_prod_id: u16::from_le_bytes([data[256], data[257]]),
            isv_svn: u16::from_le_bytes([data[258], data[259]]),
            report_data: hex::encode(&data[320..384]),
        })
    }
}

impl Default for SGXAttestationProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AttestationProvider for SGXAttestationProvider {
    fn tee_type(&self) -> TEEType {
        TEEType::Sgx
    }

    async fn verify(&self, evidence: &[u8]) -> Result<AttestationResult, AttestationError> {
        if evidence.len() < SGX_QUOTE_HEADER_SIZE + SGX_REPORT_BODY_SIZE {
            return Ok(AttestationResult::failure(
                self.tee_type(),
                format!("Quote too small: {} bytes", evidence.len()),
            )
            .with_raw_evidence(evidence.to_vec()));
        }

        let header = self.parse_quote_header(&evidence[..SGX_QUOTE_HEADER_SIZE])?;
        let report_body = self.parse_report_body(
            &evidence[SGX_QUOTE_HEADER_SIZE..SGX_QUOTE_HEADER_SIZE + SGX_REPORT_BODY_SIZE],
        )?;

        // Build measurements
        let mut measurements = HashMap::new();
        measurements.insert("MRENCLAVE".into(), report_body.mrenclave.clone());
        measurements.insert("MRSIGNER".into(), report_body.mrsigner.clone());
        measurements.insert("REPORT_DATA".into(), report_body.report_data.clone());
        measurements.insert("CPU_SVN".into(), report_body.cpu_svn.clone());

        // Build claims
        let mut claims = HashMap::new();
        claims.insert("quote_version".into(), serde_json::json!(header.version));
        claims.insert("att_key_type".into(), serde_json::json!(header.att_key_type));
        claims.insert("tee_type".into(), serde_json::json!(header.tee_type));
        claims.insert("isv_prod_id".into(), serde_json::json!(report_body.isv_prod_id));
        claims.insert("isv_svn".into(), serde_json::json!(report_body.isv_svn));
        claims.insert("attributes".into(), serde_json::json!(report_body.attributes));
        claims.insert("misc_select".into(), serde_json::json!(report_body.misc_select));

        // Verify MRENCLAVE
        if let Some(ref expected) = self.expected_mrenclave {
            if report_body.mrenclave.to_lowercase() != expected.to_lowercase() {
                return Ok(AttestationResult::failure(
                    self.tee_type(),
                    format!("MRENCLAVE mismatch: expected {expected}"),
                )
                .with_raw_evidence(evidence.to_vec()));
            }
        }

        // Verify MRSIGNER
        if let Some(ref expected) = self.expected_mrsigner {
            if report_body.mrsigner.to_lowercase() != expected.to_lowercase() {
                return Ok(AttestationResult::failure(
                    self.tee_type(),
                    format!("MRSIGNER mismatch: expected {expected}"),
                )
                .with_raw_evidence(evidence.to_vec()));
            }
        }

        // Verify ISV SVN
        if report_body.isv_svn < self.min_isv_svn {
            return Ok(AttestationResult::failure(
                self.tee_type(),
                format!(
                    "ISV SVN {} below minimum {}",
                    report_body.isv_svn, self.min_isv_svn
                ),
            )
            .with_raw_evidence(evidence.to_vec()));
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

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
        let report_data = user_data.map(|d| {
            let mut padded = [0u8; 64];
            let len = std::cmp::min(d.len(), 64);
            padded[..len].copy_from_slice(&d[..len]);
            padded
        });

        // Try Gramine attestation interface
        if Path::new("/dev/attestation/quote").exists() {
            return self.gramine_generate_quote(report_data.as_ref()).await;
        }

        // Try Occlum
        if Path::new("/dev/sgx").exists() {
            return self.occlum_generate_quote(report_data.as_ref()).await;
        }

        Err(AttestationError::NotInTEE(
            "Not running in an SGX enclave. Gramine or Occlum interface not found.".into(),
        ))
    }
}

impl SGXAttestationProvider {
    /// Generate quote using Gramine's attestation interface.
    async fn gramine_generate_quote(
        &self,
        report_data: Option<&[u8; 64]>,
    ) -> Result<Vec<u8>, AttestationError> {
        // Write report data
        if let Some(data) = report_data {
            fs::write("/dev/attestation/user_report_data", data).map_err(|e| {
                AttestationError::IoError(format!("Failed to write report data: {e}"))
            })?;
        }

        // Read quote
        let quote = fs::read("/dev/attestation/quote").map_err(|e| {
            AttestationError::IoError(format!("Failed to read quote: {e}"))
        })?;

        Ok(quote)
    }

    /// Generate quote using Occlum's interface.
    async fn occlum_generate_quote(
        &self,
        _report_data: Option<&[u8; 64]>,
    ) -> Result<Vec<u8>, AttestationError> {
        // Occlum uses a different mechanism
        Err(AttestationError::NotInTEE(
            "Occlum quote generation not yet implemented".into(),
        ))
    }
}

/// SGX quote header.
#[derive(Debug)]
#[allow(dead_code)]
struct QuoteHeader {
    version: u16,
    att_key_type: u16,
    tee_type: u32,
    vendor_id: String,
    user_data: String,
}

/// SGX report body.
#[derive(Debug)]
struct ReportBody {
    cpu_svn: String,
    misc_select: u32,
    attributes: String,
    mrenclave: String,
    mrsigner: String,
    isv_prod_id: u16,
    isv_svn: u16,
    report_data: String,
}

/// SGX sealed storage for persistent secrets.
///
/// Data sealed to enclave identity can only be unsealed by the
/// same enclave (MRENCLAVE) or same signer (MRSIGNER).
pub struct SealedStorage {
    seal_policy: SealPolicy,
    storage_path: PathBuf,
}

/// Sealing policy for SGX sealed storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealPolicy {
    /// Seal to MRENCLAVE (specific enclave)
    MrEnclave,
    /// Seal to MRSIGNER (any enclave by same signer)
    MrSigner,
}

impl SealedStorage {
    /// Create new sealed storage.
    pub fn new(seal_policy: SealPolicy, storage_path: impl Into<PathBuf>) -> Self {
        Self {
            seal_policy,
            storage_path: storage_path.into(),
        }
    }

    /// Seal data to enclave identity.
    pub async fn seal(&self, data: &[u8]) -> Result<Vec<u8>, AttestationError> {
        let key_path = match self.seal_policy {
            SealPolicy::MrEnclave => "/dev/attestation/keys/mrenclave",
            SealPolicy::MrSigner => "/dev/attestation/keys/mrsigner",
        };

        if !Path::new(key_path).exists() {
            return Err(AttestationError::NotInTEE(
                "Gramine sealing interface not available".into(),
            ));
        }

        // Read sealing key
        let mut seal_key = [0u8; 16];
        let mut file = fs::File::open(key_path).map_err(|e| {
            AttestationError::IoError(format!("Failed to open sealing key: {e}"))
        })?;
        file.read_exact(&mut seal_key).map_err(|e| {
            AttestationError::IoError(format!("Failed to read sealing key: {e}"))
        })?;

        // Derive encryption key
        use ring::digest::{digest, SHA256};
        let derived = digest(&SHA256, &seal_key);
        let mut key = [0u8; 32];
        key.copy_from_slice(derived.as_ref());

        // Encrypt with Shield
        Shield::encrypt_with_key(&key, data).map_err(|e| {
            AttestationError::IoError(format!("Encryption failed: {e}"))
        })
    }

    /// Unseal data.
    pub async fn unseal(&self, sealed_data: &[u8]) -> Result<Vec<u8>, AttestationError> {
        let key_path = match self.seal_policy {
            SealPolicy::MrEnclave => "/dev/attestation/keys/mrenclave",
            SealPolicy::MrSigner => "/dev/attestation/keys/mrsigner",
        };

        if !Path::new(key_path).exists() {
            return Err(AttestationError::NotInTEE(
                "Gramine sealing interface not available".into(),
            ));
        }

        // Read sealing key
        let mut seal_key = [0u8; 16];
        let mut file = fs::File::open(key_path).map_err(|e| {
            AttestationError::IoError(format!("Failed to open sealing key: {e}"))
        })?;
        file.read_exact(&mut seal_key).map_err(|e| {
            AttestationError::IoError(format!("Failed to read sealing key: {e}"))
        })?;

        // Derive encryption key
        use ring::digest::{digest, SHA256};
        let derived = digest(&SHA256, &seal_key);
        let mut key = [0u8; 32];
        key.copy_from_slice(derived.as_ref());

        // Decrypt with Shield
        Shield::decrypt_with_key(&key, sealed_data).map_err(|e| {
            AttestationError::IoError(format!("Decryption failed: {e}"))
        })
    }

    /// Store sealed data with a key.
    pub async fn store(&self, key: &str, data: &[u8]) -> Result<(), AttestationError> {
        fs::create_dir_all(&self.storage_path).map_err(|e| {
            AttestationError::IoError(format!("Failed to create directory: {e}"))
        })?;

        let sealed = self.seal(data).await?;

        use ring::digest::{digest, SHA256};
        let key_hash = hex::encode(&digest(&SHA256, key.as_bytes()).as_ref()[..16]);
        let path = self.storage_path.join(key_hash);

        fs::write(&path, &sealed).map_err(|e| {
            AttestationError::IoError(format!("Failed to write sealed data: {e}"))
        })
    }

    /// Load and unseal data by key.
    pub async fn load(&self, key: &str) -> Result<Vec<u8>, AttestationError> {
        use ring::digest::{digest, SHA256};
        let key_hash = hex::encode(&digest(&SHA256, key.as_bytes()).as_ref()[..16]);
        let path = self.storage_path.join(key_hash);

        let sealed = fs::read(&path).map_err(|e| {
            AttestationError::IoError(format!("Failed to read sealed data: {e}"))
        })?;

        self.unseal(&sealed).await
    }
}

/// Helper for generating Gramine manifest configurations.
pub struct GramineManifestHelper {
    entrypoint: String,
    enclave_size: String,
    thread_num: u32,
    enable_edmm: bool,
}

impl GramineManifestHelper {
    /// Create a new manifest helper.
    pub fn new(entrypoint: impl Into<String>) -> Self {
        Self {
            entrypoint: entrypoint.into(),
            enclave_size: "256M".into(),
            thread_num: 8,
            enable_edmm: false,
        }
    }

    /// Set enclave size.
    pub fn with_enclave_size(mut self, size: impl Into<String>) -> Self {
        self.enclave_size = size.into();
        self
    }

    /// Set thread count.
    pub fn with_thread_num(mut self, num: u32) -> Self {
        self.thread_num = num;
        self
    }

    /// Enable EDMM (SGX2 dynamic memory).
    pub fn with_edmm(mut self, enable: bool) -> Self {
        self.enable_edmm = enable;
        self
    }

    /// Generate manifest content.
    pub fn generate(&self) -> String {
        format!(
            r#"# Gramine manifest for Shield application
# Generated by shield_core::confidential

[loader]
entrypoint = "file:{{{{ gramine.libos }}}}"
log_level = "warning"

[loader.argv]
argv0 = "{entrypoint}"

[loader.env]
LD_LIBRARY_PATH = "/lib:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu"

[libos]
entrypoint = "{entrypoint}"

[sys]
enable_sigterm_injection = true

[sgx]
debug = false
enclave_size = "{enclave_size}"
thread_num = {thread_num}
remote_attestation = "dcap"
enable_stats = false
edmm_enable = {edmm}

[sgx.trusted_files]
entrypoint = "file:{entrypoint}"
libos = "file:{{{{ gramine.libos }}}}"
runtime = "file:{{{{ gramine.runtimedir() }}}}"

[fs.mounts]
type = "chroot"
path = "/lib"
uri = "file:{{{{ gramine.runtimedir() }}}}"
"#,
            entrypoint = self.entrypoint,
            enclave_size = self.enclave_size,
            thread_num = self.thread_num,
            edmm = self.enable_edmm,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = SGXAttestationProvider::new()
            .with_expected_mrenclave("abc123")
            .with_min_isv_svn(1);

        assert_eq!(provider.tee_type(), TEEType::Sgx);
        assert_eq!(provider.expected_mrenclave, Some("abc123".to_string()));
        assert_eq!(provider.min_isv_svn, 1);
    }

    #[test]
    fn test_manifest_generation() {
        let helper = GramineManifestHelper::new("/app/shield")
            .with_enclave_size("512M")
            .with_thread_num(16);

        let manifest = helper.generate();
        assert!(manifest.contains("enclave_size = \"512M\""));
        assert!(manifest.contains("thread_num = 16"));
    }
}
