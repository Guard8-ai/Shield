//! AWS Nitro Enclaves Attestation Provider
//!
//! Provides attestation verification for AWS Nitro Enclaves using
//! COSE-signed attestation documents with PCR measurements.
//!
//! # Cryptographic verification (CORE-CRIT-1 remediation)
//!
//! Verification is fail-closed and performs, in order:
//! 1. `COSE_Sign1` parsing (CBOR 4-tuple: protected, unprotected, payload, signature).
//! 2. Extraction of the leaf `certificate` and the full `cabundle` (DER bytes).
//! 3. Certificate-chain verification: the bundle root must equal the pinned
//!    AWS Nitro Enclaves Root G1 certificate, every link is signature-checked
//!    with real ECDSA P-384, and validity windows are enforced at the document
//!    timestamp.
//! 4. COSE ES384 signature verification: the COSE `Sig_structure` is reconstructed
//!    and the ECDSA P-384 / SHA-384 signature is verified against the leaf
//!    certificate's public key.
//! 5. Optional challenge binding (anti-replay) of the document `nonce`.
//! 6. Expected-PCR checks, only after the signature is proven authentic.
//!
//! ## Implementation note
//!
//! The cryptography is implemented with `ring` (already a hard dependency):
//! `ring::signature` provides ECDSA P-384 verification for both the COSE
//! signature (fixed r||s, ES384) and the X.509 chain (ASN.1 DER signatures). A
//! small, bounds-checked DER reader extracts the public key, signature and
//! validity fields from each certificate. Limitations: X.509 extensions
//! (`basicConstraints`, `keyUsage`) are not interpreted, and the chain is checked
//! in the order AWS publishes it (root -> intermediates -> leaf). The trust
//! anchor itself is pinned by exact DER equality to the embedded AWS root, whose
//! SHA-256 fingerprint is self-checked at runtime.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ring::signature::{UnparsedPublicKey, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_FIXED};
use subtle::ConstantTimeEq;

use super::base::{AttestationError, AttestationProvider, AttestationResult, TEEType};

/// Base64 (no PEM armor) of the pinned AWS Nitro Enclaves Root G1 certificate.
///
/// Obtained from AWS's published `AWS_NitroEnclaves_Root-G1.zip`
/// (<https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>).
const AWS_NITRO_ROOT_G1_B64: &str = "MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkFR+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6NIwLz3/Y=";

/// SHA-256 fingerprint of the DER encoding of the AWS Nitro Root G1 certificate.
///
/// The embedded root above is trusted only after its DER fingerprint is verified
/// to equal this value at runtime (see [`aws_root_der`]). This matches AWS's
/// published fingerprint `64:1A:03:21:...:79:BB:5B`.
const AWS_NITRO_ROOT_G1_SHA256: &str =
    "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";

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
    /// Test-only trust anchor override (replaces the pinned AWS root).
    #[cfg(test)]
    test_root_der: Option<Vec<u8>>,
}

impl NitroAttestationProvider {
    /// Create a new Nitro attestation provider.
    pub fn new() -> Self {
        Self {
            expected_pcrs: HashMap::new(),
            max_age_seconds: 300,
            #[cfg(test)]
            test_root_der: None,
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

    /// Inject a test trust-anchor root certificate (test-only).
    ///
    /// This replaces the pinned AWS Nitro root so the full real signature-chain
    /// verification path can be exercised with self-generated certificates.
    #[cfg(test)]
    fn with_test_root(mut self, der: Vec<u8>) -> Self {
        self.test_root_der = Some(der);
        self
    }

    /// Parse a CBOR-encoded `COSE_Sign1` document into its four components.
    fn parse_cose_sign1(data: &[u8]) -> Result<CoseSign1Parts, String> {
        let value: ciborium::Value =
            ciborium::from_reader(data).map_err(|e| format!("Failed to parse CBOR: {e}"))?;

        let array = value
            .as_array()
            .ok_or_else(|| "Expected COSE_Sign1 array".to_string())?;

        if array.len() != 4 {
            return Err("Invalid COSE_Sign1 structure".to_string());
        }

        let protected = array[0]
            .as_bytes()
            .ok_or_else(|| "Missing protected header".to_string())?
            .clone();
        let payload = array[2]
            .as_bytes()
            .ok_or_else(|| "Missing payload bytes".to_string())?
            .clone();
        let signature = array[3]
            .as_bytes()
            .ok_or_else(|| "Missing signature".to_string())?
            .clone();

        Ok(CoseSign1Parts {
            protected,
            payload,
            signature,
        })
    }

    /// Parse the attestation document payload (inner CBOR map).
    fn parse_attestation_payload(
        payload: &ciborium::Value,
    ) -> Result<NitroAttestationDocument, String> {
        let map = payload
            .as_map()
            .ok_or_else(|| "Payload is not a map".to_string())?;

        let mut doc = NitroAttestationDocument::default();

        for (key, value) in map {
            let key_str = key.as_text().unwrap_or("");
            match key_str {
                "module_id" => doc.module_id = value.as_text().map(String::from),
                "timestamp" => {
                    doc.timestamp = value.as_integer().and_then(|i| i.try_into().ok());
                }
                "digest" => doc.digest = value.as_text().map(String::from),
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
                "user_data" => doc.user_data = value.as_bytes().cloned(),
                "nonce" => doc.nonce = value.as_bytes().cloned(),
                "public_key" => doc.public_key = value.as_bytes().cloned(),
                "certificate" => doc.certificate = value.as_bytes().cloned(),
                "cabundle" => {
                    if let Some(arr) = value.as_array() {
                        doc.cabundle = arr.iter().filter_map(|v| v.as_bytes().cloned()).collect();
                    }
                }
                _ => {}
            }
        }

        Ok(doc)
    }

    /// Full fail-closed verification. Returns an error string describing the
    /// first failed check; the public `verify` maps that to a failure result.
    fn try_verify(
        &self,
        evidence: &[u8],
        expected_report_data: Option<&[u8]>,
    ) -> Result<AttestationResult, String> {
        // 1. Parse COSE_Sign1 and the inner payload.
        let parts = Self::parse_cose_sign1(evidence)?;
        let payload_value: ciborium::Value = ciborium::from_reader(parts.payload.as_slice())
            .map_err(|e| format!("Failed to parse payload: {e}"))?;
        let doc = Self::parse_attestation_payload(&payload_value)?;

        // 2. Require leaf certificate and a non-empty CA bundle.
        let leaf_der = doc
            .certificate
            .as_ref()
            .ok_or_else(|| "Attestation document missing leaf certificate".to_string())?;
        if doc.cabundle.is_empty() {
            return Err("Missing certificate bundle".to_string());
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let ts_secs = doc.timestamp.map_or(now_secs, |t| t / 1000);

        // 3. Resolve the trust anchor (pinned AWS root, or a test root).
        #[cfg(test)]
        let anchor = match &self.test_root_der {
            Some(der) => der.clone(),
            None => aws_root_der()?,
        };
        #[cfg(not(test))]
        let anchor = aws_root_der()?;

        // 4. Verify the certificate chain (real ECDSA P-384, pinned root).
        let leaf = verify_chain(leaf_der, &doc.cabundle, &anchor, ts_secs)?;

        // 5. Verify the COSE ES384 signature against the leaf public key.
        let sig_structure = build_sig_structure(&parts.protected, &parts.payload)?;
        verify_cose_signature(&leaf.spki_point, &sig_structure, &parts.signature)?;

        // 6. Challenge binding (anti-replay), constant-time. The fresh
        // server-issued challenge must appear in the document's nonce (or
        // user_data), exactly as for the SEV/MAA/SGX providers.
        if let Some(expected) = expected_report_data {
            let actual = doc
                .nonce
                .as_deref()
                .or(doc.user_data.as_deref())
                .unwrap_or(&[]);
            if actual.ct_eq(expected).unwrap_u8() != 1 {
                return Err("Attestation report data (nonce) mismatch".to_string());
            }
        }

        // 7. Expected-PCR checks, only AFTER the signature is proven authentic.
        for (pcr_idx, expected_hex) in &self.expected_pcrs {
            let expected = expected_hex.to_lowercase();
            let actual = doc.pcrs.get(pcr_idx).map(|s| s.to_lowercase());
            if actual.as_deref() != Some(&expected) {
                return Err(format!(
                    "PCR{pcr_idx} mismatch: expected {expected}, got {}",
                    actual.unwrap_or_else(|| "missing".to_string())
                ));
            }
        }

        // 8. Freshness.
        if let Some(ts_ms) = doc.timestamp {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64);
            let age_ms = now_ms.saturating_sub(ts_ms);
            if age_ms > self.max_age_seconds * 1000 {
                return Err(format!(
                    "Attestation too old: {:.1}s",
                    age_ms as f64 / 1000.0
                ));
            }
        }

        // Build the successful result.
        let mut measurements = HashMap::new();
        for (idx, value) in &doc.pcrs {
            measurements.insert(format!("PCR{idx}"), value.clone());
        }

        let mut claims = HashMap::new();
        if let Some(ref module_id) = doc.module_id {
            claims.insert("module_id".to_string(), serde_json::json!(module_id));
        }
        if let Some(timestamp) = doc.timestamp {
            claims.insert("timestamp".to_string(), serde_json::json!(timestamp));
        }
        if let Some(ref digest) = doc.digest {
            claims.insert("digest".to_string(), serde_json::json!(digest));
        }
        claims.insert(
            "cabundle_len".to_string(),
            serde_json::json!(doc.cabundle.len()),
        );
        if let Some(ref user_data) = doc.user_data {
            claims.insert(
                "user_data".to_string(),
                serde_json::json!(STANDARD.encode(user_data)),
            );
        }
        if let Some(ref nonce) = doc.nonce {
            claims.insert(
                "nonce".to_string(),
                serde_json::json!(STANDARD.encode(nonce)),
            );
        }
        if doc.public_key.is_some() {
            claims.insert("has_public_key".to_string(), serde_json::json!(true));
        }
        claims.insert(
            "certificate_chain_verified".to_string(),
            serde_json::json!(true),
        );
        claims.insert(
            "cose_signature_verified".to_string(),
            serde_json::json!(true),
        );

        let mut result = AttestationResult::success(self.tee_type())
            .with_timestamp(ts_secs)
            .with_raw_evidence(evidence.to_vec());
        result.measurements = measurements;
        result.claims = claims;
        Ok(result)
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

    async fn verify(
        &self,
        evidence: &[u8],
        expected_report_data: Option<&[u8]>,
    ) -> Result<AttestationResult, AttestationError> {
        // Fail-closed: any parse/chain/signature failure becomes a failure
        // result, never a success.
        match self.try_verify(evidence, expected_report_data) {
            Ok(result) => Ok(result),
            Err(message) => Ok(AttestationResult::failure(self.tee_type(), message)
                .with_raw_evidence(evidence.to_vec())),
        }
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
        #[cfg(not(target_os = "linux"))]
        let _ = user_data;

        Err(AttestationError::NotInTEE(
            "Not running in a Nitro Enclave (NSM device not found)".into(),
        ))
    }
}

/// Decode and validate the pinned AWS Nitro Root G1 certificate.
///
/// The embedded base64 is decoded to DER and its SHA-256 fingerprint is checked
/// against [`AWS_NITRO_ROOT_G1_SHA256`]. The fingerprint pin is the trust root:
/// if it does not match, verification fails closed (the embedded bytes are never
/// trusted on a fingerprint mismatch).
fn aws_root_der() -> Result<Vec<u8>, String> {
    let der = STANDARD
        .decode(AWS_NITRO_ROOT_G1_B64)
        .map_err(|e| format!("Failed to decode embedded AWS root: {e}"))?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &der);
    let fingerprint = hex::encode(digest.as_ref());
    if fingerprint != AWS_NITRO_ROOT_G1_SHA256 {
        return Err("Embedded AWS Nitro root fingerprint mismatch".to_string());
    }
    Ok(der)
}

/// Reconstruct and CBOR-encode the COSE `Sig_structure` for a `Sign1` message:
/// `["Signature1", protected_bstr, external_aad(empty bstr), payload_bstr]`.
fn build_sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
    let sig_structure = ciborium::Value::Array(vec![
        ciborium::Value::Text("Signature1".to_string()),
        ciborium::Value::Bytes(protected.to_vec()),
        ciborium::Value::Bytes(Vec::new()),
        ciborium::Value::Bytes(payload.to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&sig_structure, &mut out)
        .map_err(|e| format!("Failed to encode Sig_structure: {e}"))?;
    Ok(out)
}

/// Verify a COSE ES384 (ECDSA P-384 / SHA-384, fixed r||s) signature.
fn verify_cose_signature(leaf_point: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, leaf_point)
        .verify(message, signature)
        .map_err(|_| "COSE signature verification failed".to_string())
}

/// Verify an X.509 ECDSA P-384 / SHA-384 signature (ASN.1 DER `ECDSA-Sig-Value`).
fn verify_ecdsa_asn1(issuer_point: &[u8], tbs: &[u8], signature: &[u8]) -> Result<(), String> {
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, issuer_point)
        .verify(tbs, signature)
        .map_err(|_| "Certificate chain signature verification failed".to_string())
}

/// Verify the certificate chain and return the parsed leaf certificate.
///
/// The first bundle certificate must equal the pinned trust anchor (exact DER).
/// Every link is signature-verified with real ECDSA P-384, and the leaf must be
/// signed by the last bundle certificate. Validity windows are enforced for all
/// certificates at `now_secs`.
fn verify_chain(
    leaf_der: &[u8],
    cabundle: &[Vec<u8>],
    anchor: &[u8],
    now_secs: u64,
) -> Result<ParsedCert, String> {
    let root = cabundle
        .first()
        .ok_or_else(|| "Missing certificate bundle".to_string())?;
    if root.as_slice() != anchor {
        return Err("Certificate chain does not anchor to the pinned AWS Nitro root".to_string());
    }

    let mut chain: Vec<ParsedCert> = Vec::with_capacity(cabundle.len() + 1);
    for der in cabundle {
        chain.push(parse_certificate(der)?);
    }
    let leaf = parse_certificate(leaf_der)?;

    // Validity window for every certificate in the path.
    for cert in chain.iter().chain(std::iter::once(&leaf)) {
        if now_secs < cert.not_before || now_secs > cert.not_after {
            return Err("Certificate is not valid at the attestation timestamp".to_string());
        }
    }

    // Each bundle certificate must be signed by its predecessor.
    for i in 1..chain.len() {
        verify_ecdsa_asn1(&chain[i - 1].spki_point, &chain[i].tbs, &chain[i].sig)?;
    }

    // The leaf certificate must be signed by the last bundle certificate.
    let issuer = chain
        .last()
        .ok_or_else(|| "Missing certificate bundle".to_string())?;
    verify_ecdsa_asn1(&issuer.spki_point, &leaf.tbs, &leaf.sig)?;

    Ok(leaf)
}

/// A bounds-checked DER TLV element (offset/header-length/content-length).
struct Tlv {
    tag: u8,
    off: usize,
    hdr: usize,
    len: usize,
}

impl Tlv {
    fn content_start(&self) -> usize {
        self.off + self.hdr
    }
    fn end(&self) -> usize {
        self.off + self.hdr + self.len
    }
}

/// Read a single DER TLV starting at `pos`, validating all bounds.
fn read_tlv(buf: &[u8], pos: usize) -> Result<Tlv, String> {
    if pos + 2 > buf.len() {
        return Err("DER truncated".to_string());
    }
    let tag = buf[pos];
    let l0 = buf[pos + 1];
    let (len, hdr) = if (l0 & 0x80) == 0 {
        (usize::from(l0), 2)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 4 {
            return Err("DER unsupported length".to_string());
        }
        if pos + 2 + n > buf.len() {
            return Err("DER truncated length".to_string());
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(buf[pos + 2 + i]);
        }
        (len, 2 + n)
    };
    if pos + hdr + len > buf.len() {
        return Err("DER element overflows buffer".to_string());
    }
    Ok(Tlv {
        tag,
        off: pos,
        hdr,
        len,
    })
}

/// Parsed X.509 certificate fields needed for chain verification.
struct ParsedCert {
    /// Raw `tbsCertificate` DER bytes (the signed message).
    tbs: Vec<u8>,
    /// ASN.1 DER `ECDSA-Sig-Value` from the `signatureValue` BIT STRING.
    sig: Vec<u8>,
    /// Uncompressed EC public-key point `0x04 || X || Y` (97 bytes for P-384).
    spki_point: Vec<u8>,
    not_before: u64,
    not_after: u64,
}

/// Parse the minimal X.509 fields required for verification from a DER cert.
fn parse_certificate(der: &[u8]) -> Result<ParsedCert, String> {
    let cert = read_tlv(der, 0)?;
    if cert.tag != 0x30 {
        return Err("Certificate is not a SEQUENCE".to_string());
    }

    // tbsCertificate
    let tbs = read_tlv(der, cert.content_start())?;
    if tbs.tag != 0x30 {
        return Err("tbsCertificate is not a SEQUENCE".to_string());
    }
    let tbs_bytes = der[tbs.off..tbs.end()].to_vec();

    // signatureAlgorithm then signatureValue (BIT STRING).
    let sig_alg = read_tlv(der, tbs.end())?;
    let sig_val = read_tlv(der, sig_alg.end())?;
    if sig_val.tag != 0x03 || sig_val.len == 0 {
        return Err("Missing certificate signature BIT STRING".to_string());
    }
    // First BIT STRING octet is the unused-bits count (0 for DER ECDSA sigs).
    let sig = der[sig_val.content_start() + 1..sig_val.end()].to_vec();

    // Walk tbsCertificate children in order.
    let mut p = tbs.content_start();
    let first = read_tlv(der, p)?;
    if first.tag == 0xA0 {
        // optional EXPLICIT [0] version
        p = first.end();
    }
    let serial = read_tlv(der, p)?; // serialNumber
    let inner_alg = read_tlv(der, serial.end())?; // signature AlgorithmIdentifier
    let issuer = read_tlv(der, inner_alg.end())?; // issuer Name
    let validity = read_tlv(der, issuer.end())?; // validity
    if validity.tag != 0x30 {
        return Err("validity is not a SEQUENCE".to_string());
    }
    let nb = read_tlv(der, validity.content_start())?;
    let na = read_tlv(der, nb.end())?;
    let not_before = parse_asn1_time(nb.tag, &der[nb.content_start()..nb.end()])?;
    let not_after = parse_asn1_time(na.tag, &der[na.content_start()..na.end()])?;

    let subject = read_tlv(der, validity.end())?; // subject Name
    let spki = read_tlv(der, subject.end())?; // subjectPublicKeyInfo
    if spki.tag != 0x30 {
        return Err("subjectPublicKeyInfo is not a SEQUENCE".to_string());
    }
    let alg_id = read_tlv(der, spki.content_start())?;
    let pk = read_tlv(der, alg_id.end())?;
    if pk.tag != 0x03 || pk.len == 0 {
        return Err("Public key is not a BIT STRING".to_string());
    }
    let spki_point = der[pk.content_start() + 1..pk.end()].to_vec();
    if spki_point.first() != Some(&0x04) || spki_point.len() != 97 {
        return Err("Unexpected EC public-key format (expected P-384 point)".to_string());
    }

    Ok(ParsedCert {
        tbs: tbs_bytes,
        sig,
        spki_point,
        not_before,
        not_after,
    })
}

/// Parse an ASN.1 `UTCTime` (0x17) or `GeneralizedTime` (0x18) into Unix seconds.
fn parse_asn1_time(tag: u8, body: &[u8]) -> Result<u64, String> {
    let s = std::str::from_utf8(body).map_err(|_| "Invalid time encoding".to_string())?;
    let (year, rest) = match tag {
        0x17 => {
            let yy: i64 = s
                .get(0..2)
                .ok_or_else(|| "Short UTCTime".to_string())?
                .parse()
                .map_err(|_| "Bad year".to_string())?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, s.get(2..).unwrap_or(""))
        }
        0x18 => {
            let yyyy: i64 = s
                .get(0..4)
                .ok_or_else(|| "Short GeneralizedTime".to_string())?
                .parse()
                .map_err(|_| "Bad year".to_string())?;
            (yyyy, s.get(4..).unwrap_or(""))
        }
        _ => return Err("Unsupported time tag".to_string()),
    };

    let field = |a: usize, b: usize| -> Result<i64, String> {
        rest.get(a..b)
            .ok_or_else(|| "Short time field".to_string())?
            .parse()
            .map_err(|_| "Bad time field".to_string())
    };
    let mon = field(0, 2)?;
    let day = field(2, 4)?;
    let hh = field(4, 6)?;
    let mm = field(6, 8)?;
    let ss = field(8, 10)?;

    let days = days_from_civil(year, mon, day);
    let secs = days * 86_400 + hh * 3_600 + mm * 60 + ss;
    u64::try_from(secs).map_err(|_| "Negative epoch time".to_string())
}

/// Days since 1970-01-01 (proleptic Gregorian; Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
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

/// The four components of a parsed `COSE_Sign1` message.
struct CoseSign1Parts {
    /// Serialized protected header (the bstr's contents).
    protected: Vec<u8>,
    /// Serialized attestation payload (the bstr's contents).
    payload: Vec<u8>,
    /// Raw signature bytes (96-byte fixed r||s for ES384).
    signature: Vec<u8>,
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
    certificate: Option<Vec<u8>>,
    cabundle: Vec<Vec<u8>>,
}

/// vsock client for communicating with parent EC2 instance.
pub struct NitroVsockClient {
    // Read only by the Linux `send` implementation; harmless elsewhere.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    cid: u32,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
    use super::{aws_root_der, NitroAttestationProvider, NitroVsockClient};

    use ring::rand::SystemRandom;
    use ring::signature::{
        EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair, ECDSA_P384_SHA384_ASN1_SIGNING,
        ECDSA_P384_SHA384_FIXED_SIGNING,
    };

    // --- ASN.1/DER builders (real, self-contained test certificates) ----------

    const OID_EC_PUBKEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    const OID_SECP384R1: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
    const OID_ECDSA_SHA384: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
    const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];

    fn der_len(n: usize) -> Vec<u8> {
        if n < 0x80 {
            vec![n as u8]
        } else if n < 0x100 {
            vec![0x81, n as u8]
        } else {
            vec![0x82, (n >> 8) as u8, (n & 0xff) as u8]
        }
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&der_len(content.len()));
        out.extend_from_slice(content);
        out
    }

    fn ecdsa_sha384_algid() -> Vec<u8> {
        tlv(0x30, OID_ECDSA_SHA384)
    }

    fn spki(point: &[u8]) -> Vec<u8> {
        let mut alg = OID_EC_PUBKEY.to_vec();
        alg.extend_from_slice(OID_SECP384R1);
        let mut body = tlv(0x30, &alg);
        let mut bit = vec![0x00];
        bit.extend_from_slice(point);
        body.extend_from_slice(&tlv(0x03, &bit));
        tlv(0x30, &body)
    }

    fn name(cn: &str) -> Vec<u8> {
        let mut atv = OID_CN.to_vec();
        atv.extend_from_slice(&tlv(0x0c, cn.as_bytes()));
        let set = tlv(0x31, &tlv(0x30, &atv));
        tlv(0x30, &set)
    }

    fn validity(not_before: &str, not_after: &str) -> Vec<u8> {
        let mut body = tlv(0x18, not_before.as_bytes());
        body.extend_from_slice(&tlv(0x18, not_after.as_bytes()));
        tlv(0x30, &body)
    }

    fn gen_key(alg: &'static EcdsaSigningAlgorithm, rng: &SystemRandom) -> EcdsaKeyPair {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, rng).unwrap();
        EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), rng).unwrap()
    }

    fn make_cert(
        subject: &str,
        issuer: &str,
        subject_point: &[u8],
        issuer_key: &EcdsaKeyPair,
        rng: &SystemRandom,
    ) -> Vec<u8> {
        let mut tbs_body = vec![0xA0, 0x03, 0x02, 0x01, 0x02]; // version [0] = v3
        tbs_body.extend_from_slice(&[0x02, 0x01, 0x01]); // serialNumber = 1
        tbs_body.extend_from_slice(&ecdsa_sha384_algid());
        tbs_body.extend_from_slice(&name(issuer));
        tbs_body.extend_from_slice(&validity("20200101000000Z", "20400101000000Z"));
        tbs_body.extend_from_slice(&name(subject));
        tbs_body.extend_from_slice(&spki(subject_point));
        let tbs = tlv(0x30, &tbs_body);

        let sig = issuer_key.sign(rng, &tbs).unwrap(); // ASN.1 DER ECDSA-Sig-Value
        let mut bit = vec![0x00];
        bit.extend_from_slice(sig.as_ref());

        let mut cert_body = tbs;
        cert_body.extend_from_slice(&ecdsa_sha384_algid());
        cert_body.extend_from_slice(&tlv(0x03, &bit));
        tlv(0x30, &cert_body)
    }

    // --- COSE_Sign1 builders --------------------------------------------------

    fn cbor_int(i: i64) -> ciborium::Value {
        ciborium::Value::Integer(i.into())
    }

    fn payload_bytes(
        pcr0: &[u8],
        timestamp_ms: i64,
        leaf_der: &[u8],
        cabundle: &[Vec<u8>],
        nonce: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut entries = vec![
            (
                ciborium::Value::Text("module_id".into()),
                ciborium::Value::Text("i-test-enclave".into()),
            ),
            (
                ciborium::Value::Text("timestamp".into()),
                cbor_int(timestamp_ms),
            ),
            (
                ciborium::Value::Text("digest".into()),
                ciborium::Value::Text("SHA384".into()),
            ),
            (
                ciborium::Value::Text("pcrs".into()),
                ciborium::Value::Map(vec![(cbor_int(0), ciborium::Value::Bytes(pcr0.to_vec()))]),
            ),
            (
                ciborium::Value::Text("certificate".into()),
                ciborium::Value::Bytes(leaf_der.to_vec()),
            ),
            (
                ciborium::Value::Text("cabundle".into()),
                ciborium::Value::Array(
                    cabundle
                        .iter()
                        .map(|c| ciborium::Value::Bytes(c.clone()))
                        .collect(),
                ),
            ),
        ];
        if let Some(n) = nonce {
            entries.push((
                ciborium::Value::Text("nonce".into()),
                ciborium::Value::Bytes(n.to_vec()),
            ));
        }
        let mut out = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(entries), &mut out).unwrap();
        out
    }

    fn protected_bytes() -> Vec<u8> {
        // {1: -35} => alg ES384
        let map = ciborium::Value::Map(vec![(cbor_int(1), cbor_int(-35))]);
        let mut out = Vec::new();
        ciborium::into_writer(&map, &mut out).unwrap();
        out
    }

    /// Assemble a `COSE_Sign1` doc: the signature is computed over `signed_payload`
    /// while `embed_payload` is what actually appears in the document. For a
    /// genuine doc these are identical; for tamper tests they differ.
    fn assemble_cose(
        signed_payload: &[u8],
        embed_payload: &[u8],
        leaf_key: &EcdsaKeyPair,
        rng: &SystemRandom,
    ) -> Vec<u8> {
        let protected = protected_bytes();
        let sig_struct = ciborium::Value::Array(vec![
            ciborium::Value::Text("Signature1".into()),
            ciborium::Value::Bytes(protected.clone()),
            ciborium::Value::Bytes(Vec::new()),
            ciborium::Value::Bytes(signed_payload.to_vec()),
        ]);
        let mut tbs = Vec::new();
        ciborium::into_writer(&sig_struct, &mut tbs).unwrap();
        let sig = leaf_key.sign(rng, &tbs).unwrap(); // fixed 96-byte r||s
        assemble_cose_raw(&protected, embed_payload, sig.as_ref())
    }

    fn assemble_cose_raw(protected: &[u8], payload: &[u8], signature: &[u8]) -> Vec<u8> {
        let cose = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected.to_vec()),
            ciborium::Value::Map(Vec::new()),
            ciborium::Value::Bytes(payload.to_vec()),
            ciborium::Value::Bytes(signature.to_vec()),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&cose, &mut out).unwrap();
        out
    }

    fn now_ms() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// Build a CA (cert-signing) key, a leaf (COSE-signing) key, the self-signed
    /// root DER and the leaf cert DER signed by the CA.
    fn fixtures() -> (SystemRandom, EcdsaKeyPair, Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let ca = gen_key(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng);
        let leaf = gen_key(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng);
        let ca_point = ca.public_key().as_ref().to_vec();
        let leaf_point = leaf.public_key().as_ref().to_vec();
        let root_der = make_cert("aws.nitro-enclaves", "aws.nitro-enclaves", &ca_point, &ca, &rng);
        let leaf_der = make_cert("enclave-leaf", "aws.nitro-enclaves", &leaf_point, &ca, &rng);
        (rng, leaf, root_der, leaf_der)
    }

    // --- existing smoke tests -------------------------------------------------

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

    // --- root pin -------------------------------------------------------------

    #[test]
    fn test_embedded_aws_root_fingerprint_pins() {
        // The embedded AWS Nitro Root G1 must decode and match the pinned SHA-256.
        let der = aws_root_der().expect("embedded AWS root must match pinned fingerprint");
        assert_eq!(der.len(), 533);
    }

    // --- (a) genuine document verifies ---------------------------------------

    #[test]
    fn test_genuine_document_verifies() {
        let (rng, leaf, root_der, leaf_der) = fixtures();
        let pcr0 = [0u8; 48];
        let pb = payload_bytes(&pcr0, now_ms(), &leaf_der, std::slice::from_ref(&root_der), None);
        let doc = assemble_cose(&pb, &pb, &leaf, &rng);

        let provider = NitroAttestationProvider::new().with_test_root(root_der);
        let res = block_on(provider.verify(&doc, None)).unwrap();
        assert!(res.verified, "genuine doc should verify: {:?}", res.error);
        assert_eq!(
            res.claims.get("cose_signature_verified"),
            Some(&serde_json::json!(true))
        );
    }

    // --- (b) tampered payload byte is rejected -------------------------------

    #[test]
    fn test_tampered_payload_rejected() {
        let (rng, leaf, root_der, leaf_der) = fixtures();
        let pcr0 = [0u8; 48];
        let pb = payload_bytes(&pcr0, now_ms(), &leaf_der, std::slice::from_ref(&root_der), None);
        // Flip a byte inside the "i-test-enclave" module_id text: CBOR still
        // parses, but the signature (made over the original) no longer matches.
        let mut tampered = pb.clone();
        tampered[12] ^= 0x01;
        let doc = assemble_cose(&pb, &tampered, &leaf, &rng);

        let provider = NitroAttestationProvider::new().with_test_root(root_der);
        let res = block_on(provider.verify(&doc, None)).unwrap();
        assert!(!res.verified, "tampered payload must be rejected");
    }

    // --- (c) zeroed signature is rejected ------------------------------------

    #[test]
    fn test_zeroed_signature_rejected() {
        let (_rng, leaf, root_der, leaf_der) = fixtures();
        let _ = &leaf;
        let pcr0 = [0u8; 48];
        let pb = payload_bytes(&pcr0, now_ms(), &leaf_der, std::slice::from_ref(&root_der), None);
        let doc = assemble_cose_raw(&protected_bytes(), &pb, &[0u8; 96]);

        let provider = NitroAttestationProvider::new().with_test_root(root_der);
        let res = block_on(provider.verify(&doc, None)).unwrap();
        assert!(!res.verified, "zeroed signature must be rejected");
    }

    // --- (d) leaf not chaining to the trust root is rejected -----------------

    #[test]
    fn test_leaf_not_chaining_rejected() {
        let (rng, leaf, root_der, _leaf_der) = fixtures();
        // A rogue CA signs the leaf, but the bundle still presents the genuine root.
        let rogue_ca = gen_key(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng);
        let leaf_point = leaf.public_key().as_ref().to_vec();
        let rogue_leaf = make_cert("enclave-leaf", "rogue", &leaf_point, &rogue_ca, &rng);
        let pcr0 = [0u8; 48];
        let pb = payload_bytes(&pcr0, now_ms(), &rogue_leaf, std::slice::from_ref(&root_der), None);
        let doc = assemble_cose(&pb, &pb, &leaf, &rng);

        let provider = NitroAttestationProvider::new().with_test_root(root_der);
        let res = block_on(provider.verify(&doc, None)).unwrap();
        assert!(!res.verified, "leaf not signed by trust root must be rejected");
    }

    // --- (e) empty / missing cabundle is rejected ----------------------------

    #[test]
    fn test_empty_cabundle_rejected() {
        let (rng, leaf, root_der, leaf_der) = fixtures();
        let pcr0 = [0u8; 48];
        let pb = payload_bytes(&pcr0, now_ms(), &leaf_der, &[], None);
        let doc = assemble_cose(&pb, &pb, &leaf, &rng);

        let provider = NitroAttestationProvider::new().with_test_root(root_der);
        let res = block_on(provider.verify(&doc, None)).unwrap();
        assert!(!res.verified, "empty cabundle must be rejected");
    }

    // --- (f) challenge binding (anti-replay) ---------------------------------

    #[test]
    fn test_report_data_binding() {
        let (rng, leaf, root_der, leaf_der) = fixtures();
        let pcr0 = [0u8; 48];
        let nonce = b"challenge-12345";
        let pb = payload_bytes(&pcr0, now_ms(), &leaf_der, std::slice::from_ref(&root_der), Some(nonce));
        let doc = assemble_cose(&pb, &pb, &leaf, &rng);

        let provider = NitroAttestationProvider::new().with_test_root(root_der);

        // Wrong expected report data => rejected.
        let res = block_on(provider.verify(&doc, Some(b"wrong-nonce"))).unwrap();
        assert!(!res.verified, "wrong report data must be rejected");

        // Correct nonce => accepted.
        let res = block_on(provider.verify(&doc, Some(nonce))).unwrap();
        assert!(res.verified, "correct nonce should be accepted: {:?}", res.error);
    }
}
