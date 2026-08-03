//! FIDO2 Manager — Main API for `WebAuthn` operations.
//!
//! # WARNING: NON-CONFORMANT — DO NOT USE IN PRODUCTION
//!
//! This implementation does **not** satisfy the `WebAuthn` L2/L3 security model.
//! Missing properties (each is a separate phishing/bypass vector):
//!
//! 1. **Origin binding** — `clientDataJSON.origin` is never validated against
//!    `WebAuthnConfig::allowed_origins`.  Any origin can register or authenticate
//!    credentials for any relying party. *(backend-065)*
//! 2. **rpId binding** — `authenticatorData.rpIdHash` is never compared against
//!    `SHA-256(config.rp_id)`.  Credentials registered at one RP are accepted by
//!    any other RP. *(backend-065)*
//! 3. **clientDataJSON binding** — The authenticator signs a raw challenge; the
//!    `clientDataJSON` wrapper (which binds origin + operation type + challenge) is
//!    never included in the signed data.  This enables phishing and cross-origin
//!    attacks. *(backend-065)*
//! 4. **Attestation** — Authenticator identity is never verified; any device may
//!    claim any authenticator. *(backend-065)*
//!
//! See [`validate_client_data`] for the stub that will enforce (1)–(3) once wired
//! in, and the module-level docs for the migration path.

use super::config::{CredentialStore, WebAuthnConfig};
use super::credential::{ShieldCredentialStore, StoredCredential};
use super::error::{Fido2Error, Result};
use crate::Shield;
use base64::Engine;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base64 engine for FIDO2 challenge/credential encoding.
fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64_decode(data: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(data)
}

/// Challenge data for registration or authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeData {
    /// Random challenge bytes
    pub challenge: Vec<u8>,
    /// Challenge timeout timestamp
    pub expires_at: u64,
    /// Associated user ID (for authentication)
    pub user_id: Option<Vec<u8>>,
}

/// FIDO2 Manager for `WebAuthn` operations.
///
/// # Deprecated
///
/// This type does not implement the `WebAuthn` security model. It lacks origin
/// binding, rpId binding, clientDataJSON binding, and attestation — all
/// fundamental to `WebAuthn`'s phishing-resistance guarantees.
///
/// Migrate to [`webauthn-rs`](https://crates.io/crates/webauthn-rs) `0.5`.
/// This type will be removed in Shield v5.0.
#[deprecated(
    since = "4.0.0",
    note = "Fido2Manager does not implement WebAuthn origin/rpId/clientDataJSON binding \
            or attestation. Migrate to the `webauthn-rs` crate (https://crates.io/crates/webauthn-rs). \
            This type will be removed in Shield v5.0."
)]
pub struct Fido2Manager<S: CredentialStore> {
    config: WebAuthnConfig,
    store: S,
    challenges: HashMap<Vec<u8>, ChallengeData>,
}

#[allow(deprecated)]
impl Fido2Manager<ShieldCredentialStore> {
    /// Create a new FIDO2 manager with Shield-encrypted storage
    pub fn new_with_shield(config: WebAuthnConfig, shield: Shield) -> Self {
        Self {
            config,
            store: ShieldCredentialStore::new(shield),
            challenges: HashMap::new(),
        }
    }
}

#[allow(deprecated)]
impl<S: CredentialStore> Fido2Manager<S> {
    /// Create a new FIDO2 manager with custom storage
    pub fn new(config: WebAuthnConfig, store: S) -> Self {
        Self {
            config,
            store,
            challenges: HashMap::new(),
        }
    }

    /// Generate a registration challenge
    pub fn generate_registration_challenge(
        &mut self,
        user_id: &[u8],
        username: &str,
        display_name: &str,
    ) -> Result<RegistrationChallenge> {
        // Generate cryptographically secure random challenge
        let challenge = crate::random::random_vec(32)?;

        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + (u64::from(self.config.timeout_ms) / 1000);

        // Store challenge for verification
        self.challenges.insert(
            challenge.clone(),
            ChallengeData {
                challenge: challenge.clone(),
                expires_at,
                user_id: Some(user_id.to_vec()),
            },
        );

        Ok(RegistrationChallenge {
            challenge: b64_encode(&challenge),
            user_id: b64_encode(user_id),
            username: username.to_string(),
            display_name: display_name.to_string(),
            rp_id: self.config.rp_id.clone(),
            rp_name: self.config.rp_name.clone(),
            timeout_ms: self.config.timeout_ms,
        })
    }

    /// Verify registration response and store credential
    pub fn verify_registration(
        &mut self,
        challenge_b64: &str,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<StoredCredential> {
        // Decode challenge
        let challenge = b64_decode(challenge_b64).map_err(|_| Fido2Error::InvalidChallenge)?;

        // Reject empty challenges — fail-closed: an empty challenge must never succeed.
        // (backend-065: explicit guard so this path can never be silently bypassed.)
        if challenge.is_empty() {
            return Err(Fido2Error::InvalidChallenge);
        }

        // TODO(backend-065): parse and validate clientDataJSON here.
        // The caller should supply the raw clientDataJSON bytes from the browser's
        // PublicKeyCredential.response.clientDataJSON field.  Call:
        //     validate_client_data(&client_data_parsed, &self.config)?;
        // This will enforce: type == "webauthn.create", origin ∈ allowed_origins,
        // and challenge matches the server-issued challenge.

        // TODO(backend-065): verify authenticatorData.rpIdHash ==
        //     SHA-256(self.config.rp_id.as_bytes())
        // to prevent cross-RP credential reuse.

        // TODO(backend-065): verify attestation statement in authenticatorData.
        // At minimum accept "none" and "self" attestation formats.

        // Verify challenge exists and not expired
        let challenge_data = self
            .challenges
            .get(&challenge)
            .ok_or(Fido2Error::InvalidChallenge)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > challenge_data.expires_at {
            self.challenges.remove(&challenge);
            return Err(Fido2Error::InvalidChallenge);
        }

        let user_id = challenge_data
            .user_id
            .clone()
            .ok_or(Fido2Error::InvalidChallenge)?;

        // Create and store credential
        let credential = StoredCredential::new(
            credential_id,
            public_key,
            user_id.clone(),
            self.config.rp_id.clone(),
        );

        self.store.store(&user_id, &credential)?;

        // Remove used challenge
        self.challenges.remove(&challenge);

        Ok(credential)
    }

    /// Generate an authentication challenge
    pub fn generate_authentication_challenge(
        &mut self,
        user_id: &[u8],
    ) -> Result<AuthenticationChallenge> {
        // Get user's credentials
        let credentials = self.store.get(user_id)?;

        if credentials.is_empty() {
            return Err(Fido2Error::CredentialNotFound);
        }

        // Generate challenge
        let challenge = crate::random::random_vec(32)?;

        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + (u64::from(self.config.timeout_ms) / 1000);

        // Store challenge
        self.challenges.insert(
            challenge.clone(),
            ChallengeData {
                challenge: challenge.clone(),
                expires_at,
                user_id: Some(user_id.to_vec()),
            },
        );

        // Build allowed credentials list
        let allowed_credentials: Vec<_> = credentials
            .iter()
            .map(|c| AllowedCredential {
                id: b64_encode(&c.credential_id),
                credential_type: "public-key".to_string(),
            })
            .collect();

        Ok(AuthenticationChallenge {
            challenge: b64_encode(&challenge),
            allowed_credentials,
            timeout_ms: self.config.timeout_ms,
            rp_id: self.config.rp_id.clone(),
        })
    }

    /// Verify authentication response
    pub fn verify_authentication(
        &mut self,
        challenge_b64: &str,
        credential_id: &[u8],
        signature: &[u8],
        counter: u32,
    ) -> Result<AuthenticationResult> {
        // Decode challenge
        let challenge = b64_decode(challenge_b64).map_err(|_| Fido2Error::InvalidChallenge)?;

        // Reject empty challenges — fail-closed: an empty challenge must never succeed.
        // (backend-065: explicit guard.)
        if challenge.is_empty() {
            return Err(Fido2Error::InvalidChallenge);
        }

        // TODO(backend-065): parse and validate clientDataJSON here.
        // The caller should supply the raw clientDataJSON bytes from the browser's
        // PublicKeyCredential.response.clientDataJSON field.  Call:
        //     validate_client_data(&client_data_parsed, &self.config)?;
        // This will enforce: type == "webauthn.get", origin ∈ allowed_origins,
        // and challenge matches the server-issued challenge.

        // TODO(backend-065): verify authenticatorData.rpIdHash ==
        //     SHA-256(self.config.rp_id.as_bytes())
        // to prevent cross-RP credential acceptance.

        // TODO(backend-065): verify authenticatorData flags:
        // - UP (user presence) bit must be set.
        // - UV (user verification) bit must be set if userVerification == "required".

        // Verify challenge exists and not expired
        let challenge_data = self
            .challenges
            .get(&challenge)
            .ok_or(Fido2Error::InvalidChallenge)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > challenge_data.expires_at {
            self.challenges.remove(&challenge);
            return Err(Fido2Error::InvalidChallenge);
        }

        let user_id = challenge_data
            .user_id
            .clone()
            .ok_or(Fido2Error::InvalidChallenge)?;

        // Get stored credential
        let credentials = self.store.get(&user_id)?;
        let stored_cred = credentials
            .iter()
            .find(|c| c.credential_id == credential_id)
            .ok_or(Fido2Error::CredentialNotFound)?;

        // Verify counter increased (replay protection)
        if counter <= stored_cred.counter {
            return Err(Fido2Error::CounterDecreased);
        }

        // Verify the ECDSA P-256 (ES256) signature with the stored credential's
        // PUBLIC key. This is real asymmetric verification, as WebAuthn requires:
        // only the holder of the authenticator's private key can produce a valid
        // signature. (The previous implementation used the public key as an
        // HMAC secret, so anyone who learned the public key could forge auth.)
        // Signed data: challenge || credential_id || counter (domain separation).
        let mut sign_data = Vec::with_capacity(challenge.len() + credential_id.len() + 4);
        sign_data.extend_from_slice(&challenge);
        sign_data.extend_from_slice(credential_id);
        sign_data.extend_from_slice(&counter.to_le_bytes());
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &stored_cred.public_key);
        public_key
            .verify(&sign_data, signature)
            .map_err(|_| Fido2Error::InvalidSignature)?;

        // Update counter
        self.store
            .update_counter(&user_id, credential_id, counter)?;

        // Remove used challenge
        self.challenges.remove(&challenge);

        Ok(AuthenticationResult {
            user_id,
            credential_id: credential_id.to_vec(),
            counter,
            success: true,
        })
    }

    /// List all credentials for a user
    pub fn list_credentials(&self, user_id: &[u8]) -> Result<Vec<StoredCredential>> {
        self.store.get(user_id)
    }

    /// Delete a credential
    pub fn delete_credential(&mut self, user_id: &[u8], credential_id: &[u8]) -> Result<()> {
        self.store.delete(user_id, credential_id)
    }
}

// ─── Stub validation types ────────────────────────────────────────────────────
//
// The types and function below are the scaffolding for proper WebAuthn
// clientDataJSON validation (backend-065).  `validate_client_data` enforces the
// three bindings that the rest of this module currently skips:
//   • operation type  ("webauthn.create" / "webauthn.get")
//   • origin          (must be in `WebAuthnConfig::allowed_origins`)
//   • challenge       (must be non-empty; full binding to server state is done
//                      by the caller via the challenge map)
//
// Wire this into `verify_registration` and `verify_authentication` once the
// caller supplies the raw `clientDataJSON` bytes. (backend-065)

/// Parsed representation of the `WebAuthn` `clientDataJSON` object.
///
/// In a conformant implementation the browser supplies this as a
/// base64url-encoded JSON blob inside
/// `PublicKeyCredential.response.clientDataJSON`.
///
/// Currently unused by `Fido2Manager` because `verify_registration` and
/// `verify_authentication` do not yet accept `clientDataJSON` bytes.
/// See `backend-065`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientData {
    /// Must be `"webauthn.create"` for registration or `"webauthn.get"` for
    /// authentication.
    #[serde(rename = "type")]
    pub operation_type: String,
    /// The HTTP origin of the page that created the credential (e.g.
    /// `"https://example.com"`).
    pub origin: String,
    /// The base64url-encoded challenge that the server issued.
    pub challenge: String,
    /// Whether cross-origin embedding is allowed (optional in spec).
    #[serde(rename = "crossOrigin", default)]
    pub cross_origin: bool,
}

/// Validate a parsed `ClientData` object against the relying-party config.
///
/// This is a **stub** — it enforces the three cheapest bindings:
/// 1. `type` must match `expected_type` (`"webauthn.create"` or `"webauthn.get"`)
/// 2. `origin` must appear in `config.allowed_origins`
/// 3. `challenge` (base64url-decoded) must be non-empty
///
/// It does **not** yet verify the challenge against server state (the caller
/// must do that via the challenge map) and does **not** yet hash and compare
/// `rpIdHash` (see TODO in `verify_registration` / `verify_authentication`).
///
/// Wire this in once `verify_registration` and `verify_authentication` accept
/// raw `clientDataJSON` bytes. (backend-065)
pub fn validate_client_data(
    client_data: &ClientData,
    config: &WebAuthnConfig,
    expected_type: &str,
) -> std::result::Result<(), Fido2Error> {
    // 1. Operation-type check ("webauthn.create" vs "webauthn.get")
    if client_data.operation_type != expected_type {
        return Err(Fido2Error::WebAuthn(format!(
            "clientDataJSON.type mismatch: expected {:?}, got {:?}",
            expected_type, client_data.operation_type
        )));
    }

    // 2. Origin binding — TODO(backend-065): currently the only enforcement
    //    point for origin; must be called from verify_registration /
    //    verify_authentication once clientDataJSON is threaded through.
    if !config.allowed_origins.contains(&client_data.origin) {
        return Err(Fido2Error::WebAuthn(format!(
            "clientDataJSON.origin {:?} not in allowed_origins",
            client_data.origin
        )));
    }

    // 3. Challenge must be non-empty (full server-state binding is done by
    //    the caller via the challenge HashMap).
    let challenge_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&client_data.challenge)
        .map_err(|_| Fido2Error::InvalidChallenge)?;
    if challenge_bytes.is_empty() {
        return Err(Fido2Error::InvalidChallenge);
    }

    // TODO(backend-065): return `challenge_bytes` to the caller so it can be
    //   looked up in the challenge HashMap (avoids double-decode).

    Ok(())
}

// ─── Public challenge / response types ───────────────────────────────────────

/// Registration challenge sent to client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationChallenge {
    pub challenge: String, // base64-encoded
    pub user_id: String,   // base64-encoded
    pub username: String,
    pub display_name: String,
    pub rp_id: String,
    pub rp_name: String,
    pub timeout_ms: u32,
}

/// Authentication challenge sent to client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    pub challenge: String, // base64-encoded
    pub allowed_credentials: Vec<AllowedCredential>,
    pub timeout_ms: u32,
    pub rp_id: String,
}

/// Allowed credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedCredential {
    pub id: String, // base64-encoded credential ID
    #[serde(rename = "type")]
    pub credential_type: String, // "public-key"
}

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub user_id: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub counter: u32,
    pub success: bool,
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    fn create_test_manager() -> Fido2Manager<ShieldCredentialStore> {
        let config = WebAuthnConfig::new("example.com", "Test App", "https://example.com");
        let shield = Shield::new("test_password", "fido2.test");
        Fido2Manager::new_with_shield(config, shield)
    }

    /// A throwaway ECDSA P-256 authenticator: returns the signing key, its RNG,
    /// and the SEC1 uncompressed public-key point that gets registered.
    fn gen_authenticator() -> (EcdsaKeyPair, SystemRandom, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        (key_pair, rng, public_key)
    }

    /// Produce a real ES256 signature from the authenticator's PRIVATE key over
    /// `challenge || credential_id || counter`.
    fn compute_test_signature(
        key_pair: &EcdsaKeyPair,
        rng: &SystemRandom,
        challenge_b64: &str,
        credential_id: &[u8],
        counter: u32,
    ) -> Vec<u8> {
        let challenge = b64_decode(challenge_b64).unwrap();
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&challenge);
        sign_data.extend_from_slice(credential_id);
        sign_data.extend_from_slice(&counter.to_le_bytes());
        key_pair.sign(rng, &sign_data).unwrap().as_ref().to_vec()
    }

    #[test]
    fn test_registration_flow() {
        let mut manager = create_test_manager();
        let user_id = b"user123";

        // Generate challenge
        let challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();

        assert!(!challenge.challenge.is_empty());
        assert_eq!(challenge.username, "testuser");

        // Simulate registration
        let credential_id = b"cred_id_123".to_vec();
        let public_key = b"public_key_data".to_vec();

        let stored = manager
            .verify_registration(&challenge.challenge, credential_id.clone(), public_key)
            .unwrap();

        assert_eq!(stored.credential_id, credential_id);
        assert_eq!(stored.user_id, user_id);
    }

    #[test]
    fn test_authentication_flow() {
        let mut manager = create_test_manager();
        let user_id = b"user123";
        let credential_id = b"cred_id_123".to_vec();
        let (key_pair, rng, public_key) = gen_authenticator();

        // Register first
        let reg_challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();
        manager
            .verify_registration(
                &reg_challenge.challenge,
                credential_id.clone(),
                public_key.clone(),
            )
            .unwrap();

        // Generate auth challenge
        let auth_challenge = manager.generate_authentication_challenge(user_id).unwrap();
        assert!(!auth_challenge.challenge.is_empty());
        assert_eq!(auth_challenge.allowed_credentials.len(), 1);

        // Sign with the authenticator's private key (real ES256).
        let signature = compute_test_signature(
            &key_pair,
            &rng,
            &auth_challenge.challenge,
            &credential_id,
            1,
        );

        let result = manager
            .verify_authentication(&auth_challenge.challenge, &credential_id, &signature, 1)
            .unwrap();

        assert!(result.success);
        assert_eq!(result.user_id, user_id);
        assert_eq!(result.counter, 1);
    }

    #[test]
    fn test_forged_signature_with_public_key_rejected() {
        // Regression for the audit finding: knowing the (public) credential key
        // must NOT let an attacker forge auth. The old code HMAC'd with the
        // public key, so HMAC(public_key, data) verified. With real ES256 that
        // attempt is just an invalid signature.
        let mut manager = create_test_manager();
        let user_id = b"user123";
        let credential_id = b"cred_id_123".to_vec();
        let (_key_pair, _rng, public_key) = gen_authenticator();

        let reg_challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();
        manager
            .verify_registration(
                &reg_challenge.challenge,
                credential_id.clone(),
                public_key.clone(),
            )
            .unwrap();

        let auth_challenge = manager.generate_authentication_challenge(user_id).unwrap();

        // Attacker forges the old HMAC-with-public-key "signature".
        let challenge = b64_decode(&auth_challenge.challenge).unwrap();
        let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &public_key);
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&challenge);
        sign_data.extend_from_slice(&credential_id);
        sign_data.extend_from_slice(&1u32.to_le_bytes());
        let forged = ring::hmac::sign(&hmac_key, &sign_data).as_ref().to_vec();

        let result =
            manager.verify_authentication(&auth_challenge.challenge, &credential_id, &forged, 1);
        assert!(matches!(result, Err(Fido2Error::InvalidSignature)));
    }

    #[test]
    fn test_authentication_invalid_signature() {
        let mut manager = create_test_manager();
        let user_id = b"user123";
        let credential_id = b"cred_id_123".to_vec();

        // Register
        let reg_challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();
        manager
            .verify_registration(
                &reg_challenge.challenge,
                credential_id.clone(),
                b"public_key_data".to_vec(),
            )
            .unwrap();

        // Generate auth challenge
        let auth_challenge = manager.generate_authentication_challenge(user_id).unwrap();

        // Use an invalid signature
        let result = manager.verify_authentication(
            &auth_challenge.challenge,
            &credential_id,
            b"invalid_signature",
            1,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Fido2Error::InvalidSignature));
    }

    #[test]
    fn test_counter_replay_protection() {
        let mut manager = create_test_manager();
        let user_id = b"user123";
        let credential_id = b"cred_id_123".to_vec();
        let (key_pair, rng, public_key) = gen_authenticator();

        // Register
        let reg_challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();
        manager
            .verify_registration(
                &reg_challenge.challenge,
                credential_id.clone(),
                public_key.clone(),
            )
            .unwrap();

        // First authentication with valid signature
        let auth_challenge = manager.generate_authentication_challenge(user_id).unwrap();
        let sig1 = compute_test_signature(
            &key_pair,
            &rng,
            &auth_challenge.challenge,
            &credential_id,
            1,
        );
        manager
            .verify_authentication(&auth_challenge.challenge, &credential_id, &sig1, 1)
            .unwrap();

        // Second authentication with same counter should fail (replay)
        let auth_challenge2 = manager.generate_authentication_challenge(user_id).unwrap();
        let sig2 = compute_test_signature(
            &key_pair,
            &rng,
            &auth_challenge2.challenge,
            &credential_id,
            1,
        );
        let result =
            manager.verify_authentication(&auth_challenge2.challenge, &credential_id, &sig2, 1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Fido2Error::CounterDecreased));
    }
}
