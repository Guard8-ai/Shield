//! Shared JWS/JWT signature verification for JWT-based attestation providers
//! (GCP SEV-SNP and Azure MAA).
//!
//! The whole point of an attestation JWT is that it is **signed** by the cloud
//! provider's attestation service. Verifying that signature against a trusted,
//! published key — and pinning the audience/issuer and enforcing expiry — is
//! what makes the claims trustworthy. This module centralises that logic so the
//! providers cannot drift apart.

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use subtle::ConstantTimeEq;

use super::base::AttestationError;

/// A trusted issuer signing key used to verify attestation JWTs.
pub(crate) struct TrustedJwtKey {
    kid: Option<String>,
    alg: Algorithm,
    key: DecodingKey,
}

/// Verifies attestation JWTs against a set of trusted issuer keys.
///
/// Holds no trusted keys by default, so [`JwtVerifier::verify`] fails closed
/// until at least one key is configured.
#[derive(Default)]
pub(crate) struct JwtVerifier {
    trusted_keys: Vec<TrustedJwtKey>,
    issuer: Option<String>,
    audiences: Vec<String>,
}

impl JwtVerifier {
    /// Pin the expected token issuer (`iss` claim).
    pub fn set_issuer(&mut self, issuer: impl Into<String>) {
        self.issuer = Some(issuer.into());
    }

    /// Set the expected audience (`aud` claim). At least one audience must be
    /// configured for verification to succeed.
    pub fn set_audience(&mut self, audience: impl Into<String>) {
        self.audiences = vec![audience.into()];
    }

    /// Add a trusted ECDSA P-256 (ES256) public key in SPKI PEM form.
    pub fn add_es256_pem(&mut self, kid: Option<&str>, pem: &str) -> Result<(), AttestationError> {
        let key = DecodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| {
            AttestationError::InvalidFormat(format!("Invalid ES256 public key: {e}"))
        })?;
        self.trusted_keys.push(TrustedJwtKey {
            kid: kid.map(String::from),
            alg: Algorithm::ES256,
            key,
        });
        Ok(())
    }

    /// Add a trusted RSA (RS256) public key in SPKI PEM form.
    pub fn add_rs256_pem(&mut self, kid: Option<&str>, pem: &str) -> Result<(), AttestationError> {
        let key = DecodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| {
            AttestationError::InvalidFormat(format!("Invalid RS256 public key: {e}"))
        })?;
        self.trusted_keys.push(TrustedJwtKey {
            kid: kid.map(String::from),
            alg: Algorithm::RS256,
            key,
        });
        Ok(())
    }

    /// Import RSA signing keys from a JWKS JSON document (e.g. Google's or
    /// Azure's published certificate set). Returns the number of keys added.
    pub fn add_jwks_json(&mut self, jwks_json: &str) -> Result<usize, AttestationError> {
        let doc: serde_json::Value = serde_json::from_str(jwks_json)
            .map_err(|e| AttestationError::InvalidFormat(format!("Invalid JWKS JSON: {e}")))?;
        let keys = doc
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or_else(|| AttestationError::InvalidFormat("JWKS missing 'keys' array".into()))?;

        let mut added = 0;
        for jwk in keys {
            if jwk.get("kty").and_then(serde_json::Value::as_str) != Some("RSA") {
                continue;
            }
            if let Some(use_) = jwk.get("use").and_then(serde_json::Value::as_str) {
                if use_ != "sig" {
                    continue;
                }
            }
            let (Some(n), Some(e)) = (
                jwk.get("n").and_then(serde_json::Value::as_str),
                jwk.get("e").and_then(serde_json::Value::as_str),
            ) else {
                continue;
            };
            let Ok(key) = DecodingKey::from_rsa_components(n, e) else {
                continue;
            };
            let kid = jwk
                .get("kid")
                .and_then(serde_json::Value::as_str)
                .map(String::from);
            self.trusted_keys.push(TrustedJwtKey {
                kid,
                alg: Algorithm::RS256,
                key,
            });
            added += 1;
        }
        Ok(added)
    }

    /// Whether any trusted key is configured.
    pub fn is_empty(&self) -> bool {
        self.trusted_keys.is_empty()
    }

    /// Verify the JWS signature of `token` and validate its registered claims,
    /// deserialising the payload into `T`.
    ///
    /// Returns `Err(reason)` on any failure (bad signature, untrusted key,
    /// expired, wrong audience/issuer, algorithm mismatch). The caller should
    /// treat any error as a hard verification failure.
    pub fn verify<T: DeserializeOwned>(&self, token: &str) -> Result<T, String> {
        if self.trusted_keys.is_empty() {
            return Err("No trusted signing key configured; refusing to verify (fail-closed)".into());
        }
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
            // attacker cannot downgrade (e.g. to `none`, or HS256 keyed on the
            // RSA public key).
            if header.alg != k.alg {
                continue;
            }
            let mut validation = Validation::new(k.alg);
            validation.validate_exp = true;
            validation.validate_nbf = true;
            if self.audiences.is_empty() {
                // No audience configured => cannot safely accept. Fail closed.
                return Err("No audience configured; refusing to verify (fail-closed)".into());
            }
            validation.set_audience(&self.audiences);
            if let Some(ref iss) = self.issuer {
                validation.set_issuer(std::slice::from_ref(iss));
            }
            match decode::<T>(token, &k.key, &validation) {
                Ok(data) => return Ok(data.claims),
                Err(e) => last_err = format!("JWT verification failed: {e}"),
            }
        }
        Err(last_err)
    }
}

/// Constant-time check that a hex-encoded TEE report-data field carries the
/// expected challenge in its leading bytes (the remainder is zero-padding).
///
/// Used to bind a fresh server-issued challenge into the attestation so a
/// captured-and-replayed token is rejected (anti-replay).
pub(crate) fn report_data_matches(report_data_hex: Option<&str>, challenge: &[u8]) -> bool {
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
