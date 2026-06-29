//! Confidential Computing Support for Shield
//!
//! Provides attestation verification and TEE-aware key management for:
//! - AWS Nitro Enclaves
//! - GCP Confidential VMs (AMD SEV-SNP)
//! - Azure Confidential Containers (MAA)
//! - Intel SGX (Gramine/Occlum)
//!
//! # Example
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use shield_core::confidential::{
//!     AttestationProvider, NitroAttestationProvider, TEEKeyManager,
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let provider = Arc::new(
//!     NitroAttestationProvider::new()
//!         .with_expected_pcr(0, "abc123...")
//! );
//!
//! // A fresh, server-generated random challenge that the enclave must bind
//! // into its attestation report-data (anti-replay / freshness).
//! let challenge: [u8; 32] = [0u8; 32]; // use a CSPRNG value in production
//! let attestation_doc = provider.generate_evidence(Some(&challenge)).await?;
//! let result = provider.verify(&attestation_doc, Some(&challenge)).await?;
//! if result.verified {
//!     let key_manager = TEEKeyManager::new("password", "service", provider);
//!     let _key = key_manager
//!         .get_key(&attestation_doc, "encryption", Some(&challenge))
//!         .await?;
//! }
//! # Ok(())
//! # }
//! ```

mod base;
mod jwt;
mod maa;
mod nitro;
#[cfg(feature = "openapi")]
mod openapi;
mod sev;
mod sgx;

pub use base::{
    AttestationError, AttestationProvider, AttestationResult, KeyReleasePolicy, TEEKeyManager,
    TEEType,
};
pub use maa::{AzureKeyVaultSKR, ConfidentialContainerSidecar, MAAAttestationProvider};
pub use nitro::{NitroAttestationProvider, NitroVsockClient, NitroVsockServer};
pub use sev::{ConfidentialSpaceProvider, GCPSecretManager, SEVAttestationProvider};
pub use sgx::{GramineManifestHelper, SGXAttestationProvider, SealedStorage};

#[cfg(feature = "openapi")]
pub use openapi::{
    decrypt_data, encrypt_data, get_attestation, health_check, verify_attestation,
    AttestationRequest, AttestationResponse, OpenAPISchemas, ShieldConfidentialApi,
};
