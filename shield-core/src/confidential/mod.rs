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
//! ```rust,ignore
//! use shield_core::confidential::{
//!     AttestationProvider, NitroAttestationProvider, TEEKeyManager,
//! };
//!
//! let provider = NitroAttestationProvider::new()
//!     .with_expected_pcr(0, "abc123...");
//!
//! let result = provider.verify(&attestation_doc).await?;
//! if result.verified {
//!     let key = key_manager.get_key(&attestation_doc, "encryption").await?;
//! }
//! ```

mod base;
mod nitro;
mod sev;
mod maa;
mod sgx;
#[cfg(feature = "openapi")]
mod openapi;

pub use base::{
    AttestationError, AttestationProvider, AttestationResult, KeyReleasePolicy, TEEKeyManager,
    TEEType,
};
pub use nitro::{NitroAttestationProvider, NitroVsockClient, NitroVsockServer};
pub use sev::{ConfidentialSpaceProvider, GCPSecretManager, SEVAttestationProvider};
pub use maa::{AzureKeyVaultSKR, ConfidentialContainerSidecar, MAAAttestationProvider};
pub use sgx::{GramineManifestHelper, SGXAttestationProvider, SealedStorage};

#[cfg(feature = "openapi")]
pub use openapi::{AttestationRequest, AttestationResponse, OpenAPISchemas};
