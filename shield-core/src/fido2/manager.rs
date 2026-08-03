//! FIDO2 Manager — Main API for `WebAuthn` operations.

use super::config::{CredentialStore, WebAuthnConfig};
use super::credential::{ShieldCredentialStore, StoredCredential};
use super::error::{Fido2Error, Result};
use crate::Shield;
use base64::Engine;
use ring::digest;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// authenticatorData layout (FIDO2 spec §6.1):
//   bytes  0..32: rpIdHash
//   byte  32    : flags  (bit 0 = UP, bit 2 = UV, bit 6 = AT)
//   bytes 33..37: signCount (u32 big-endian)
const AUTHENTICATOR_DATA_MIN_LEN: usize = 37;
const RPID_HASH_LEN: usize = 32;
const FLAGS_OFFSET: usize = 32;
const COUNTER_OFFSET: usize = 33;
const FLAGS_UP: u8 = 0x01;

fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64_decode(data: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(data)
}

fn sha256(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
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
/// Implements origin binding, rpId binding, clientDataJSON binding, and
/// counter-based replay protection per the `WebAuthn` Level 2 specification.
///
/// Registration and authentication both require the raw `clientDataJSON`
/// and `authenticatorData` bytes from the browser's
/// `PublicKeyCredential.response` object.
pub struct Fido2Manager<S: CredentialStore> {
    config: WebAuthnConfig,
    store: S,
    challenges: HashMap<Vec<u8>, ChallengeData>,
}

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
        let challenge = crate::random::random_vec(32)?;

        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + (u64::from(self.config.timeout_ms) / 1000);

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

    /// Verify a `WebAuthn` registration response and store the credential.
    ///
    /// `client_data_json` — raw UTF-8 bytes of `clientDataJSON` from the
    /// browser's `PublicKeyCredential.response.clientDataJSON`.
    ///
    /// `authenticator_data` — raw bytes of `authenticatorData` from the
    /// browser's `PublicKeyCredential.response.authenticatorData`.
    /// Must be at least 37 bytes: rpIdHash(32) + flags(1) + signCount(4).
    ///
    /// `public_key` — the DER-encoded ECDSA P-256 public key extracted from
    /// `authenticatorData.attestedCredentialData`.
    pub fn verify_registration(
        &mut self,
        challenge_b64: &str,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        client_data_json: &[u8],
        authenticator_data: &[u8],
    ) -> Result<StoredCredential> {
        // Parse and validate clientDataJSON (origin, type, non-empty challenge)
        let client_data: ClientData = serde_json::from_slice(client_data_json)
            .map_err(|e| Fido2Error::WebAuthn(format!("invalid clientDataJSON: {e}")))?;
        validate_client_data(&client_data, &self.config, "webauthn.create")?;

        // Decode the challenge_b64 the server issued
        let challenge = b64_decode(challenge_b64).map_err(|_| Fido2Error::InvalidChallenge)?;
        if challenge.is_empty() {
            return Err(Fido2Error::InvalidChallenge);
        }

        // Confirm clientDataJSON.challenge matches the server-issued challenge
        let cdj_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&client_data.challenge)
            .map_err(|_| Fido2Error::InvalidChallenge)?;
        if cdj_challenge != challenge {
            return Err(Fido2Error::InvalidChallenge);
        }

        // Validate authenticatorData structure
        if authenticator_data.len() < AUTHENTICATOR_DATA_MIN_LEN {
            return Err(Fido2Error::WebAuthn(
                "authenticatorData too short".into(),
            ));
        }

        // Verify rpIdHash == SHA-256(rp_id)
        let expected_rp_hash = sha256(self.config.rp_id.as_bytes());
        if authenticator_data[..RPID_HASH_LEN] != *expected_rp_hash {
            return Err(Fido2Error::WebAuthn("rpIdHash mismatch".into()));
        }

        // Require user presence
        if authenticator_data[FLAGS_OFFSET] & FLAGS_UP == 0 {
            return Err(Fido2Error::UserVerificationFailed);
        }

        // Verify challenge is live and not expired
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

        let credential = StoredCredential::new(
            credential_id,
            public_key,
            user_id.clone(),
            self.config.rp_id.clone(),
        );

        self.store.store(&user_id, &credential)?;
        self.challenges.remove(&challenge);

        Ok(credential)
    }

    /// Generate an authentication challenge
    pub fn generate_authentication_challenge(
        &mut self,
        user_id: &[u8],
    ) -> Result<AuthenticationChallenge> {
        let credentials = self.store.get(user_id)?;
        if credentials.is_empty() {
            return Err(Fido2Error::CredentialNotFound);
        }

        let challenge = crate::random::random_vec(32)?;

        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + (u64::from(self.config.timeout_ms) / 1000);

        self.challenges.insert(
            challenge.clone(),
            ChallengeData {
                challenge: challenge.clone(),
                expires_at,
                user_id: Some(user_id.to_vec()),
            },
        );

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

    /// Verify a `WebAuthn` authentication response.
    ///
    /// `client_data_json` — raw UTF-8 bytes of `clientDataJSON` from the
    /// browser's `PublicKeyCredential.response.clientDataJSON`.
    ///
    /// `authenticator_data` — raw bytes of `authenticatorData` from the
    /// browser's `PublicKeyCredential.response.authenticatorData`.
    /// The counter (signCount) is extracted from bytes 33–36 (big-endian).
    ///
    /// The signature is verified over `authenticatorData || SHA-256(clientDataJSON)`
    /// as required by the `WebAuthn` specification.
    pub fn verify_authentication(
        &mut self,
        challenge_b64: &str,
        credential_id: &[u8],
        signature: &[u8],
        client_data_json: &[u8],
        authenticator_data: &[u8],
    ) -> Result<AuthenticationResult> {
        // Parse and validate clientDataJSON
        let client_data: ClientData = serde_json::from_slice(client_data_json)
            .map_err(|e| Fido2Error::WebAuthn(format!("invalid clientDataJSON: {e}")))?;
        validate_client_data(&client_data, &self.config, "webauthn.get")?;

        let challenge = b64_decode(challenge_b64).map_err(|_| Fido2Error::InvalidChallenge)?;
        if challenge.is_empty() {
            return Err(Fido2Error::InvalidChallenge);
        }

        // Confirm clientDataJSON.challenge matches the server-issued challenge
        let cdj_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&client_data.challenge)
            .map_err(|_| Fido2Error::InvalidChallenge)?;
        if cdj_challenge != challenge {
            return Err(Fido2Error::InvalidChallenge);
        }

        // Validate authenticatorData structure
        if authenticator_data.len() < AUTHENTICATOR_DATA_MIN_LEN {
            return Err(Fido2Error::WebAuthn(
                "authenticatorData too short".into(),
            ));
        }

        // Verify rpIdHash == SHA-256(rp_id)
        let expected_rp_hash = sha256(self.config.rp_id.as_bytes());
        if authenticator_data[..RPID_HASH_LEN] != *expected_rp_hash {
            return Err(Fido2Error::WebAuthn("rpIdHash mismatch".into()));
        }

        // Require user presence
        if authenticator_data[FLAGS_OFFSET] & FLAGS_UP == 0 {
            return Err(Fido2Error::UserVerificationFailed);
        }

        // Extract counter from authenticatorData bytes 33–36 (big-endian)
        let counter = u32::from_be_bytes([
            authenticator_data[COUNTER_OFFSET],
            authenticator_data[COUNTER_OFFSET + 1],
            authenticator_data[COUNTER_OFFSET + 2],
            authenticator_data[COUNTER_OFFSET + 3],
        ]);

        // Verify challenge is live and not expired
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

        // Look up stored credential
        let credentials = self.store.get(&user_id)?;
        let stored_cred = credentials
            .iter()
            .find(|c| c.credential_id == credential_id)
            .ok_or(Fido2Error::CredentialNotFound)?;

        // Counter must have advanced (replay protection)
        if counter <= stored_cred.counter {
            return Err(Fido2Error::CounterDecreased);
        }

        // Verify ECDSA P-256 signature over: authenticatorData || SHA-256(clientDataJSON)
        let client_data_hash = sha256(client_data_json);
        let mut signed_data =
            Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
        signed_data.extend_from_slice(authenticator_data);
        signed_data.extend_from_slice(&client_data_hash);

        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &stored_cred.public_key);
        public_key
            .verify(&signed_data, signature)
            .map_err(|_| Fido2Error::InvalidSignature)?;

        self.store
            .update_counter(&user_id, credential_id, counter)?;
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

// ─── clientDataJSON validation ────────────────────────────────────────────────

/// Parsed representation of the `WebAuthn` `clientDataJSON` object.
///
/// The browser supplies this as a base64url-encoded JSON blob inside
/// `PublicKeyCredential.response.clientDataJSON`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientData {
    /// `"webauthn.create"` for registration or `"webauthn.get"` for authentication.
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
/// Enforces:
/// 1. `type` must match `expected_type` (`"webauthn.create"` or `"webauthn.get"`)
/// 2. `origin` must appear in `config.allowed_origins`
/// 3. `challenge` (base64url-decoded) must be non-empty
pub fn validate_client_data(
    client_data: &ClientData,
    config: &WebAuthnConfig,
    expected_type: &str,
) -> std::result::Result<(), Fido2Error> {
    if client_data.operation_type != expected_type {
        return Err(Fido2Error::WebAuthn(format!(
            "clientDataJSON.type mismatch: expected {:?}, got {:?}",
            expected_type, client_data.operation_type
        )));
    }

    if !config.allowed_origins.contains(&client_data.origin) {
        return Err(Fido2Error::WebAuthn(format!(
            "clientDataJSON.origin {:?} not in allowed_origins",
            client_data.origin
        )));
    }

    let challenge_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&client_data.challenge)
        .map_err(|_| Fido2Error::InvalidChallenge)?;
    if challenge_bytes.is_empty() {
        return Err(Fido2Error::InvalidChallenge);
    }

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
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    const TEST_RP_ID: &str = "example.com";
    const TEST_ORIGIN: &str = "https://example.com";

    fn create_test_manager() -> Fido2Manager<ShieldCredentialStore> {
        let config = WebAuthnConfig::new(TEST_RP_ID, "Test App", TEST_ORIGIN);
        let shield = Shield::new("test_password", "fido2.test");
        Fido2Manager::new_with_shield(config, shield)
    }

    fn gen_authenticator() -> (EcdsaKeyPair, SystemRandom, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        (key_pair, rng, public_key)
    }

    /// Build a minimal authenticatorData: rpIdHash(32) || flags(1) || counter(4 BE).
    fn build_authenticator_data(rp_id: &str, counter: u32) -> Vec<u8> {
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&sha256(rp_id.as_bytes()));
        auth_data.push(0x05); // UP + UV flags
        auth_data.extend_from_slice(&counter.to_be_bytes());
        auth_data
    }

    /// Build a clientDataJSON bytes for the given type, origin, and challenge.
    fn build_client_data_json(op_type: &str, origin: &str, challenge_b64: &str) -> Vec<u8> {
        let challenge_bytes =
            base64::engine::general_purpose::STANDARD.decode(challenge_b64).unwrap();
        let challenge_b64url =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
        format!(
            r#"{{"type":"{op_type}","challenge":"{challenge_b64url}","origin":"{origin}","crossOrigin":false}}"#
        )
        .into_bytes()
    }

    /// Sign `authenticatorData || SHA-256(clientDataJSON)` with an ES256 key.
    fn sign_webauthn(
        key_pair: &EcdsaKeyPair,
        rng: &SystemRandom,
        authenticator_data: &[u8],
        client_data_json: &[u8],
    ) -> Vec<u8> {
        let cdj_hash = sha256(client_data_json);
        let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
        signed.extend_from_slice(authenticator_data);
        signed.extend_from_slice(&cdj_hash);
        key_pair.sign(rng, &signed).unwrap().as_ref().to_vec()
    }

    #[test]
    fn test_registration_flow() {
        let mut manager = create_test_manager();
        let user_id = b"user123";

        let challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();
        assert!(!challenge.challenge.is_empty());
        assert_eq!(challenge.username, "testuser");

        let credential_id = b"cred_id_123".to_vec();
        let public_key = b"public_key_data".to_vec();
        let auth_data = build_authenticator_data(TEST_RP_ID, 0);
        let cdj = build_client_data_json("webauthn.create", TEST_ORIGIN, &challenge.challenge);

        let stored = manager
            .verify_registration(
                &challenge.challenge,
                credential_id.clone(),
                public_key,
                &cdj,
                &auth_data,
            )
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

        // Register
        let reg_challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();
        let reg_auth_data = build_authenticator_data(TEST_RP_ID, 0);
        let reg_cdj =
            build_client_data_json("webauthn.create", TEST_ORIGIN, &reg_challenge.challenge);
        manager
            .verify_registration(
                &reg_challenge.challenge,
                credential_id.clone(),
                public_key.clone(),
                &reg_cdj,
                &reg_auth_data,
            )
            .unwrap();

        // Authenticate
        let auth_challenge = manager.generate_authentication_challenge(user_id).unwrap();
        assert!(!auth_challenge.challenge.is_empty());
        assert_eq!(auth_challenge.allowed_credentials.len(), 1);

        let auth_data = build_authenticator_data(TEST_RP_ID, 1);
        let cdj = build_client_data_json("webauthn.get", TEST_ORIGIN, &auth_challenge.challenge);
        let signature = sign_webauthn(&key_pair, &rng, &auth_data, &cdj);

        let result = manager
            .verify_authentication(
                &auth_challenge.challenge,
                &credential_id,
                &signature,
                &cdj,
                &auth_data,
            )
            .unwrap();

        assert!(result.success);
        assert_eq!(result.user_id, user_id);
        assert_eq!(result.counter, 1);
    }

    #[test]
    fn test_forged_signature_with_public_key_rejected() {
        let mut manager = create_test_manager();
        let user_id = b"user123";
        let credential_id = b"cred_id_123".to_vec();
        let (_key_pair, _rng, public_key) = gen_authenticator();

        let reg_challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();
        let reg_auth_data = build_authenticator_data(TEST_RP_ID, 0);
        let reg_cdj =
            build_client_data_json("webauthn.create", TEST_ORIGIN, &reg_challenge.challenge);
        manager
            .verify_registration(
                &reg_challenge.challenge,
                credential_id.clone(),
                public_key.clone(),
                &reg_cdj,
                &reg_auth_data,
            )
            .unwrap();

        let auth_challenge = manager.generate_authentication_challenge(user_id).unwrap();
        let auth_data = build_authenticator_data(TEST_RP_ID, 1);
        let cdj = build_client_data_json("webauthn.get", TEST_ORIGIN, &auth_challenge.challenge);

        // Attacker forges an HMAC-with-public-key "signature" over the real signed data.
        let cdj_hash = sha256(&cdj);
        let mut signed = Vec::new();
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(&cdj_hash);
        let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &public_key);
        let forged = ring::hmac::sign(&hmac_key, &signed).as_ref().to_vec();

        let result = manager.verify_authentication(
            &auth_challenge.challenge,
            &credential_id,
            &forged,
            &cdj,
            &auth_data,
        );
        assert!(matches!(result, Err(Fido2Error::InvalidSignature)));
    }

    #[test]
    fn test_authentication_invalid_signature() {
        let mut manager = create_test_manager();
        let user_id = b"user123";
        let credential_id = b"cred_id_123".to_vec();

        let reg_challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();
        let reg_auth_data = build_authenticator_data(TEST_RP_ID, 0);
        let reg_cdj =
            build_client_data_json("webauthn.create", TEST_ORIGIN, &reg_challenge.challenge);
        manager
            .verify_registration(
                &reg_challenge.challenge,
                credential_id.clone(),
                b"public_key_data".to_vec(),
                &reg_cdj,
                &reg_auth_data,
            )
            .unwrap();

        let auth_challenge = manager.generate_authentication_challenge(user_id).unwrap();
        let auth_data = build_authenticator_data(TEST_RP_ID, 1);
        let cdj = build_client_data_json("webauthn.get", TEST_ORIGIN, &auth_challenge.challenge);

        let result = manager.verify_authentication(
            &auth_challenge.challenge,
            &credential_id,
            b"invalid_signature",
            &cdj,
            &auth_data,
        );
        assert!(matches!(result.unwrap_err(), Fido2Error::InvalidSignature));
    }

    #[test]
    fn test_counter_replay_protection() {
        let mut manager = create_test_manager();
        let user_id = b"user123";
        let credential_id = b"cred_id_123".to_vec();
        let (key_pair, rng, public_key) = gen_authenticator();

        let reg_challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();
        let reg_auth_data = build_authenticator_data(TEST_RP_ID, 0);
        let reg_cdj =
            build_client_data_json("webauthn.create", TEST_ORIGIN, &reg_challenge.challenge);
        manager
            .verify_registration(
                &reg_challenge.challenge,
                credential_id.clone(),
                public_key.clone(),
                &reg_cdj,
                &reg_auth_data,
            )
            .unwrap();

        // First auth — counter = 1
        let auth_challenge1 = manager.generate_authentication_challenge(user_id).unwrap();
        let auth_data1 = build_authenticator_data(TEST_RP_ID, 1);
        let cdj1 =
            build_client_data_json("webauthn.get", TEST_ORIGIN, &auth_challenge1.challenge);
        let sig1 = sign_webauthn(&key_pair, &rng, &auth_data1, &cdj1);
        manager
            .verify_authentication(
                &auth_challenge1.challenge,
                &credential_id,
                &sig1,
                &cdj1,
                &auth_data1,
            )
            .unwrap();

        // Second auth with same counter = 1 should fail (replay)
        let auth_challenge2 = manager.generate_authentication_challenge(user_id).unwrap();
        let auth_data2 = build_authenticator_data(TEST_RP_ID, 1); // same counter
        let cdj2 =
            build_client_data_json("webauthn.get", TEST_ORIGIN, &auth_challenge2.challenge);
        let sig2 = sign_webauthn(&key_pair, &rng, &auth_data2, &cdj2);
        let result = manager.verify_authentication(
            &auth_challenge2.challenge,
            &credential_id,
            &sig2,
            &cdj2,
            &auth_data2,
        );
        assert!(matches!(result.unwrap_err(), Fido2Error::CounterDecreased));
    }

    #[test]
    fn test_wrong_origin_rejected() {
        let mut manager = create_test_manager();
        let user_id = b"user123";
        let credential_id = b"cred_id_123".to_vec();
        let (key_pair, rng, public_key) = gen_authenticator();

        let reg_challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();
        let reg_auth_data = build_authenticator_data(TEST_RP_ID, 0);
        let reg_cdj =
            build_client_data_json("webauthn.create", TEST_ORIGIN, &reg_challenge.challenge);
        manager
            .verify_registration(
                &reg_challenge.challenge,
                credential_id.clone(),
                public_key,
                &reg_cdj,
                &reg_auth_data,
            )
            .unwrap();

        let auth_challenge = manager.generate_authentication_challenge(user_id).unwrap();
        let auth_data = build_authenticator_data(TEST_RP_ID, 1);
        // Phishing origin
        let cdj = build_client_data_json("webauthn.get", "https://evil.com", &auth_challenge.challenge);
        let sig = sign_webauthn(&key_pair, &rng, &auth_data, &cdj);

        let result = manager.verify_authentication(
            &auth_challenge.challenge,
            &credential_id,
            &sig,
            &cdj,
            &auth_data,
        );
        assert!(matches!(result, Err(Fido2Error::WebAuthn(_))));
    }

    #[test]
    fn test_wrong_rp_id_rejected() {
        let mut manager = create_test_manager();
        let user_id = b"user123";
        let credential_id = b"cred_id_123".to_vec();

        let reg_challenge = manager
            .generate_registration_challenge(user_id, "testuser", "Test User")
            .unwrap();
        let reg_cdj =
            build_client_data_json("webauthn.create", TEST_ORIGIN, &reg_challenge.challenge);

        // authenticatorData with wrong rpId hash
        let wrong_auth_data = build_authenticator_data("evil.com", 0);
        let result = manager.verify_registration(
            &reg_challenge.challenge,
            credential_id.clone(),
            b"pubkey".to_vec(),
            &reg_cdj,
            &wrong_auth_data,
        );
        assert!(matches!(result, Err(Fido2Error::WebAuthn(_))));
    }
}
