//! Intel SGX Attestation Provider
//!
//! Provides REAL attestation verification for Intel SGX enclaves using
//! DCAP (Data Center Attestation Primitives), backed by the pure-Rust
//! [`dcap-qvl`](https://crates.io/crates/dcap-qvl) quote verification library.
//!
//! Verification performed by [`dcap_qvl::verify::verify`]:
//! 1. Parses the DCAP quote (header + SGX report body + ECDSA signature data).
//! 2. Verifies the ECDSA-P256 quote signature and the QE report signature.
//! 3. Verifies the PCK certificate chain up to the **Intel SGX Root CA**.
//! 4. Checks the PCK CRL and evaluates the **TCB status** against Intel TCB info
//!    and QE identity (the *collateral*).
//!
//! Verification is **fail-closed**: if collateral is not available (neither
//! configured on the provider nor fetchable from a PCCS), or if any
//! cryptographic / TCB / CRL check fails, [`SGXAttestationProvider::verify`]
//! returns a *failure* result and never reports `verified = true`. This is the
//! remediation for CORE-CRIT-1 (quote signatures were previously never checked).

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ring::digest::{digest, SHA256};
use ring::hmac;
use subtle::ConstantTimeEq;

use dcap_qvl::verify::verify as dcap_verify;
use dcap_qvl::QuoteCollateralV3;

use super::base::{AttestationError, AttestationProvider, AttestationResult, TEEType};
use crate::Shield;

/// Intel SGX attestation provider (DCAP / `dcap-qvl`).
///
/// Cryptographically verifies DCAP quotes and, only after the quote is proven
/// genuine, enforces additional policy gates:
/// - acceptable TCB status (default: `UpToDate` only),
/// - challenge binding of `report_data` (anti-replay), compared in constant time,
/// - expected MRENCLAVE / MRSIGNER,
/// - minimum ISV SVN.
pub struct SGXAttestationProvider {
    expected_mrenclave: Option<String>,
    expected_mrsigner: Option<String>,
    min_isv_svn: u16,
    /// PCCS/PCS base URL used to fetch quote collateral when none is configured.
    pccs_url: Option<String>,
    /// Raw `QuoteCollateralV3` JSON supplied for offline / air-gapped / test use.
    collateral_json: Option<Vec<u8>>,
    /// TCB statuses that are considered acceptable. Defaults to `["UpToDate"]`.
    allowed_tcb_statuses: Vec<String>,
    /// Optional pinned verification time (Unix seconds). Used for KATs against
    /// archived collateral; defaults to the current system time.
    verification_time: Option<u64>,
}

impl SGXAttestationProvider {
    /// Create a new SGX attestation provider (default-deny TCB: `UpToDate` only).
    pub fn new() -> Self {
        Self {
            expected_mrenclave: None,
            expected_mrsigner: None,
            min_isv_svn: 0,
            pccs_url: None,
            collateral_json: None,
            allowed_tcb_statuses: vec!["UpToDate".to_string()],
            verification_time: None,
        }
    }

    /// Set expected MRENCLAVE value.
    #[must_use]
    pub fn with_expected_mrenclave(mut self, value: impl Into<String>) -> Self {
        self.expected_mrenclave = Some(value.into());
        self
    }

    /// Set expected MRSIGNER value.
    #[must_use]
    pub fn with_expected_mrsigner(mut self, value: impl Into<String>) -> Self {
        self.expected_mrsigner = Some(value.into());
        self
    }

    /// Set minimum ISV SVN.
    #[must_use]
    pub fn with_min_isv_svn(mut self, svn: u16) -> Self {
        self.min_isv_svn = svn;
        self
    }

    /// Set PCCS URL used to fetch quote collateral (used only when no collateral
    /// JSON is configured, and only when the `async` feature is enabled).
    #[must_use]
    pub fn with_pccs_url(mut self, url: impl Into<String>) -> Self {
        self.pccs_url = Some(url.into());
        self
    }

    /// Supply quote collateral (`QuoteCollateralV3` JSON) directly, for offline
    /// / air-gapped operation and deterministic testing.
    #[must_use]
    pub fn with_collateral_json(mut self, collateral: impl Into<Vec<u8>>) -> Self {
        self.collateral_json = Some(collateral.into());
        self
    }

    /// Add an acceptable TCB status (e.g. `"SWHardeningNeeded"`). Defaults to
    /// `UpToDate` only; statuses such as `OutOfDate`/`Revoked` are rejected
    /// unless explicitly added here.
    #[must_use]
    pub fn with_allowed_tcb_status(mut self, status: impl Into<String>) -> Self {
        self.allowed_tcb_statuses.push(status.into());
        self
    }

    /// Pin the verification timestamp (Unix seconds). Mainly for known-answer
    /// tests against archived collateral whose validity window is in the past.
    #[must_use]
    pub fn with_verification_time(mut self, unix_secs: u64) -> Self {
        self.verification_time = Some(unix_secs);
        self
    }

    /// Acquire quote collateral: configured JSON first, otherwise fetch from the
    /// PCCS (when `async`). Returns an error (fail-closed) if neither is available.
    async fn acquire_collateral(&self, evidence: &[u8]) -> Result<QuoteCollateralV3, String> {
        if let Some(raw) = &self.collateral_json {
            return serde_json::from_slice(raw)
                .map_err(|e| format!("invalid collateral JSON: {e}"));
        }

        #[cfg(feature = "async")]
        {
            if let Some(url) = &self.pccs_url {
                let client = dcap_qvl::collateral::CollateralClient::with_default_http(url.clone())
                    .map_err(|e| format!("failed to build collateral client: {e}"))?;
                return client
                    .fetch(evidence)
                    .await
                    .map_err(|e| format!("failed to fetch collateral from PCCS: {e}"));
            }
        }
        #[cfg(not(feature = "async"))]
        let _ = evidence;

        Err("no collateral configured and no PCCS URL available".to_string())
    }

    /// Constant-time challenge binding: are the first `expected.len()` bytes of
    /// `report_data` equal to `expected`?
    fn report_data_matches(report_data: &[u8; 64], expected: &[u8]) -> bool {
        if expected.is_empty() || expected.len() > report_data.len() {
            return false;
        }
        bool::from(report_data[..expected.len()].ct_eq(expected))
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

    async fn verify(
        &self,
        evidence: &[u8],
        expected_report_data: Option<&[u8]>,
    ) -> Result<AttestationResult, AttestationError> {
        let fail = |msg: String| {
            Ok(AttestationResult::failure(TEEType::Sgx, msg).with_raw_evidence(evidence.to_vec()))
        };

        // ---- Step 1+2: acquire collateral, then perform REAL DCAP verification.
        // dcap-qvl parses the quote, verifies the ECDSA quote/QE signatures, the
        // PCK chain to the Intel SGX Root CA, the PCK CRL, and the TCB status.
        // FAIL CLOSED if collateral is unavailable or any check fails.
        let collateral = match self.acquire_collateral(evidence).await {
            Ok(c) => c,
            Err(e) => return fail(format!("fail-closed: {e}")),
        };

        let now = self.verification_time.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        });

        let report = match dcap_verify(evidence, &collateral, now) {
            Ok(r) => r,
            Err(e) => return fail(format!("DCAP quote verification failed: {e}")),
        };

        // The quote is now cryptographically genuine. Everything below is an
        // ADDITIONAL policy gate applied to the *verified* report.

        // ---- Step 3a: TCB status must be acceptable (default-deny).
        if !self
            .allowed_tcb_statuses
            .iter()
            .any(|s| s == &report.status)
        {
            return fail(format!(
                "TCB status not acceptable: {} (allowed: {:?})",
                report.status, self.allowed_tcb_statuses
            ));
        }

        // Must be an SGX enclave report (reject TDX etc.).
        let Some(sgx) = report.report.as_sgx() else {
            return fail("verified quote is not an SGX enclave report".to_string());
        };

        let mrenclave = hex::encode(sgx.mr_enclave);
        let mrsigner = hex::encode(sgx.mr_signer);

        // ---- Step 4: challenge binding (anti-replay), constant-time compare.
        // The fresh server-issued challenge must appear in the enclave's
        // report_data, exactly as for the SEV/MAA providers.
        if let Some(expected) = expected_report_data {
            if !Self::report_data_matches(&sgx.report_data, expected) {
                return fail("report_data (challenge) mismatch".to_string());
            }
        }

        // ---- Step 3b: expected MRENCLAVE / MRSIGNER / min ISV SVN gates.
        if let Some(ref expected) = self.expected_mrenclave {
            if !bool::from(
                mrenclave
                    .as_bytes()
                    .ct_eq(expected.to_lowercase().as_bytes()),
            ) {
                return fail(format!("MRENCLAVE mismatch: expected {expected}"));
            }
        }
        if let Some(ref expected) = self.expected_mrsigner {
            if !bool::from(
                mrsigner
                    .as_bytes()
                    .ct_eq(expected.to_lowercase().as_bytes()),
            ) {
                return fail(format!("MRSIGNER mismatch: expected {expected}"));
            }
        }
        if sgx.isv_svn < self.min_isv_svn {
            return fail(format!(
                "ISV SVN {} below minimum {}",
                sgx.isv_svn, self.min_isv_svn
            ));
        }

        // ---- Build the successful, verified result.
        let mut measurements = HashMap::new();
        measurements.insert("MRENCLAVE".into(), mrenclave);
        measurements.insert("MRSIGNER".into(), mrsigner);
        measurements.insert("REPORT_DATA".into(), hex::encode(sgx.report_data));
        measurements.insert("CPU_SVN".into(), hex::encode(sgx.cpu_svn));

        let mut claims = HashMap::new();
        claims.insert("tcb_status".into(), serde_json::json!(report.status));
        claims.insert(
            "advisory_ids".into(),
            serde_json::json!(report.advisory_ids),
        );
        claims.insert("isv_prod_id".into(), serde_json::json!(sgx.isv_prod_id));
        claims.insert("isv_svn".into(), serde_json::json!(sgx.isv_svn));
        claims.insert(
            "attributes".into(),
            serde_json::json!(hex::encode(sgx.attributes)),
        );
        claims.insert("misc_select".into(), serde_json::json!(sgx.misc_select));

        let mut result = AttestationResult::success(self.tee_type())
            .with_timestamp(now)
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

        // Both Gramine and Occlum (0.30+) expose /dev/attestation/
        if Path::new("/dev/attestation/quote").exists() {
            return Self::attestation_dev_generate_quote(report_data.as_ref());
        }

        // Occlum also exposes /dev/sgx with the attestation interface
        if Path::new("/dev/sgx").exists() {
            return Self::sgx_dev_generate_quote(report_data.as_ref());
        }

        Err(AttestationError::NotInTEE(
            "Not running in an SGX enclave. No attestation interface found.".into(),
        ))
    }
}

impl SGXAttestationProvider {
    /// Generate quote via `/dev/attestation/` interface (Gramine and Occlum 0.30+).
    fn attestation_dev_generate_quote(
        report_data: Option<&[u8; 64]>,
    ) -> Result<Vec<u8>, AttestationError> {
        if let Some(data) = report_data {
            fs::write("/dev/attestation/user_report_data", data).map_err(|e| {
                AttestationError::IoError(format!("Failed to write report data: {e}"))
            })?;
        }

        fs::read("/dev/attestation/quote")
            .map_err(|e| AttestationError::IoError(format!("Failed to read quote: {e}")))
    }

    /// Generate quote via `/dev/sgx` interface (Occlum legacy).
    ///
    /// Reads the SGX quote from `/dev/sgx/quote` after writing report data
    /// to `/dev/sgx/user_report_data`.
    fn sgx_dev_generate_quote(report_data: Option<&[u8; 64]>) -> Result<Vec<u8>, AttestationError> {
        if let Some(data) = report_data {
            fs::write("/dev/sgx/user_report_data", data).map_err(|e| {
                AttestationError::IoError(format!("Failed to write SGX report data: {e}"))
            })?;
        }

        fs::read("/dev/sgx/quote")
            .map_err(|e| AttestationError::IoError(format!("Failed to read SGX quote: {e}")))
    }
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
    pub fn seal(&self, data: &[u8]) -> Result<Vec<u8>, AttestationError> {
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
        let mut file = fs::File::open(key_path)
            .map_err(|e| AttestationError::IoError(format!("Failed to open sealing key: {e}")))?;
        file.read_exact(&mut seal_key)
            .map_err(|e| AttestationError::IoError(format!("Failed to read sealing key: {e}")))?;

        // Derive encryption key using keyed HMAC (not unkeyed SHA256)
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &seal_key);
        let derived = hmac::sign(&hmac_key, b"shield-sealed-storage-v1");
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived.as_ref()[..32]);

        // Encrypt with Shield
        Shield::encrypt_with_key(&key, data)
            .map_err(|e| AttestationError::IoError(format!("Encryption failed: {e}")))
    }

    /// Unseal data.
    pub fn unseal(&self, sealed_data: &[u8]) -> Result<Vec<u8>, AttestationError> {
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
        let mut file = fs::File::open(key_path)
            .map_err(|e| AttestationError::IoError(format!("Failed to open sealing key: {e}")))?;
        file.read_exact(&mut seal_key)
            .map_err(|e| AttestationError::IoError(format!("Failed to read sealing key: {e}")))?;

        // Derive encryption key using keyed HMAC (not unkeyed SHA256)
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &seal_key);
        let derived = hmac::sign(&hmac_key, b"shield-sealed-storage-v1");
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived.as_ref()[..32]);

        // Decrypt with Shield
        Shield::decrypt_with_key(&key, sealed_data)
            .map_err(|e| AttestationError::IoError(format!("Decryption failed: {e}")))
    }

    /// Store sealed data with a key.
    pub fn store(&self, key: &str, data: &[u8]) -> Result<(), AttestationError> {
        let sealed = self.seal(data)?;

        let key_hash = hex::encode(&digest(&SHA256, key.as_bytes()).as_ref()[..16]);
        let path = self.storage_path.join(key_hash);

        fs::create_dir_all(&self.storage_path)
            .map_err(|e| AttestationError::IoError(format!("Failed to create directory: {e}")))?;

        fs::write(&path, &sealed)
            .map_err(|e| AttestationError::IoError(format!("Failed to write sealed data: {e}")))
    }

    /// Load and unseal data by key.
    pub fn load(&self, key: &str) -> Result<Vec<u8>, AttestationError> {
        let key_hash = hex::encode(&digest(&SHA256, key.as_bytes()).as_ref()[..16]);
        let path = self.storage_path.join(key_hash);

        let sealed = fs::read(&path)
            .map_err(|e| AttestationError::IoError(format!("Failed to read sealed data: {e}")))?;

        self.unseal(&sealed)
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
    #[must_use]
    pub fn with_enclave_size(mut self, size: impl Into<String>) -> Self {
        self.enclave_size = size.into();
        self
    }

    /// Set thread count.
    #[must_use]
    pub fn with_thread_num(mut self, num: u32) -> Self {
        self.thread_num = num;
        self
    }

    /// Enable EDMM (SGX2 dynamic memory).
    #[must_use]
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

    // Real Intel DCAP sample vendored from the dcap-qvl crate (genuine SGX
    // quote + matching Intel collateral). Used as a known-answer test.
    const SAMPLE_QUOTE: &[u8] = include_bytes!("testdata/sgx_quote");
    const SAMPLE_COLLATERAL: &[u8] = include_bytes!("testdata/sgx_quote_collateral.json");
    const MISMATCHED_COLLATERAL: &[u8] = include_bytes!("testdata/tdx_quote_collateral.json");

    // Timestamp pinned inside the sample collateral's validity window so the KAT
    // is deterministic (the archived collateral is no longer "current").
    const PINNED_NOW: u64 = 1_752_919_277;
    // Expected measurements of the genuine sample quote (verified via dcap-qvl).
    const SAMPLE_MRENCLAVE: &str =
        "33d8736db756ed4997e04ba358d27833188f1932ff7b1d156904d3f560452fbb";
    const SAMPLE_MRSIGNER: &str =
        "815f42f11cf64430c30bab7816ba596a1da0130c3b028b673133a66cf9a3e0e6";
    // The genuine sample's TCB status is not UpToDate; allow it explicitly.
    const SAMPLE_TCB_STATUS: &str = "ConfigurationAndSWHardeningNeeded";

    #[test]
    fn test_provider_creation() {
        let provider = SGXAttestationProvider::new()
            .with_expected_mrenclave("abc123")
            .with_min_isv_svn(1);

        assert_eq!(provider.tee_type(), TEEType::Sgx);
        assert_eq!(provider.expected_mrenclave, Some("abc123".to_string()));
        assert_eq!(provider.min_isv_svn, 1);
        // Default-deny TCB policy.
        assert_eq!(provider.allowed_tcb_statuses, vec!["UpToDate".to_string()]);
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

    #[test]
    fn report_data_binding_is_constant_time_and_correct() {
        let mut rd = [0u8; 64];
        for (i, b) in rd.iter_mut().enumerate() {
            *b = i as u8;
        }
        // Matching prefix accepted.
        assert!(SGXAttestationProvider::report_data_matches(&rd, &rd[..32]));
        assert!(SGXAttestationProvider::report_data_matches(&rd, &rd[..]));
        // Wrong byte rejected.
        let mut wrong = rd[..32].to_vec();
        wrong[0] ^= 0xff;
        assert!(!SGXAttestationProvider::report_data_matches(&rd, &wrong));
        // Empty / oversized expected rejected.
        assert!(!SGXAttestationProvider::report_data_matches(&rd, &[]));
        assert!(!SGXAttestationProvider::report_data_matches(
            &rd, &[0u8; 65]
        ));
    }

    #[tokio::test]
    async fn malformed_quote_is_rejected() {
        // Too-short / garbage evidence must never verify (fail-closed).
        let provider =
            SGXAttestationProvider::new().with_collateral_json(SAMPLE_COLLATERAL.to_vec());
        let result = provider.verify(&[0u8; 16], None).await.unwrap();
        assert!(!result.verified, "malformed quote must be rejected");
    }

    #[tokio::test]
    async fn no_collateral_fails_closed() {
        // No collateral configured and no PCCS URL => must fail closed even for a
        // genuine quote.
        let provider = SGXAttestationProvider::new();
        let result = provider.verify(SAMPLE_QUOTE, None).await.unwrap();
        assert!(!result.verified, "must fail closed without collateral");
        assert!(result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("fail-closed"));
    }

    #[tokio::test]
    async fn mismatched_collateral_is_rejected() {
        // Genuine quote, wrong collateral => cryptographic verification fails.
        let provider =
            SGXAttestationProvider::new().with_collateral_json(MISMATCHED_COLLATERAL.to_vec());
        let result = provider.verify(SAMPLE_QUOTE, None).await.unwrap();
        assert!(!result.verified, "mismatched collateral must be rejected");
    }

    #[tokio::test]
    async fn tampered_quote_is_rejected() {
        // Flip a byte in the signed quote body => signature check must fail.
        let mut tampered = SAMPLE_QUOTE.to_vec();
        tampered[600] ^= 0xff;
        let provider = SGXAttestationProvider::new()
            .with_collateral_json(SAMPLE_COLLATERAL.to_vec())
            .with_allowed_tcb_status(SAMPLE_TCB_STATUS)
            .with_verification_time(PINNED_NOW);
        let result = provider.verify(&tampered, None).await.unwrap();
        assert!(!result.verified, "tampered quote must be rejected");
    }

    #[tokio::test]
    async fn genuine_sample_quote_verifies_kat() {
        // POSITIVE KAT: a genuine Intel SGX quote with matching collateral
        // verifies cryptographically (ECDSA sig + PCK chain to Intel root + TCB).
        let provider = SGXAttestationProvider::new()
            .with_collateral_json(SAMPLE_COLLATERAL.to_vec())
            .with_allowed_tcb_status(SAMPLE_TCB_STATUS)
            .with_verification_time(PINNED_NOW);
        let result = provider.verify(SAMPLE_QUOTE, None).await.unwrap();
        assert!(
            result.verified,
            "genuine sample must verify: {:?}",
            result.error
        );
        assert_eq!(
            result.measurements.get("MRENCLAVE").map(String::as_str),
            Some(SAMPLE_MRENCLAVE)
        );
        assert_eq!(
            result.measurements.get("MRSIGNER").map(String::as_str),
            Some(SAMPLE_MRSIGNER)
        );
        assert_eq!(
            result.claims.get("tcb_status").and_then(|v| v.as_str()),
            Some(SAMPLE_TCB_STATUS)
        );
    }

    #[tokio::test]
    async fn default_tcb_policy_rejects_non_uptodate() {
        // Without explicitly allowing the sample's status, default-deny rejects it
        // (cryptographically genuine, but TCB not UpToDate).
        let provider = SGXAttestationProvider::new()
            .with_collateral_json(SAMPLE_COLLATERAL.to_vec())
            .with_verification_time(PINNED_NOW);
        let result = provider.verify(SAMPLE_QUOTE, None).await.unwrap();
        assert!(
            !result.verified,
            "default-deny TCB must reject non-UpToDate"
        );
        assert!(result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("TCB status"));
    }

    #[tokio::test]
    async fn wrong_expected_report_data_is_rejected() {
        // Genuine quote but a challenge/nonce that does not match report_data.
        let provider = SGXAttestationProvider::new()
            .with_collateral_json(SAMPLE_COLLATERAL.to_vec())
            .with_allowed_tcb_status(SAMPLE_TCB_STATUS)
            .with_verification_time(PINNED_NOW);
        let result = provider
            .verify(SAMPLE_QUOTE, Some(&[0xABu8; 32]))
            .await
            .unwrap();
        assert!(!result.verified, "wrong report_data must be rejected");
        assert!(result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("report_data"));
    }
}
