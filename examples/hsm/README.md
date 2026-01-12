# Shield HSM Integration Examples

This directory contains examples for integrating Shield with Hardware Security Modules (HSMs).

## Overview

Shield uses symmetric cryptography, making HSM integration straightforward. The HSM stores and protects the master key, while Shield handles encryption/decryption operations.

## Supported HSMs

| HSM | Interface | Status |
|-----|-----------|--------|
| AWS CloudHSM | PKCS#11 | Example provided |
| Azure Key Vault | REST API | Example provided |
| HashiCorp Vault | REST API | Example provided |
| YubiHSM 2 | PKCS#11 | Example provided |
| Thales Luna | PKCS#11 | Planned |

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────┐
│   Application   │────▶│    Shield    │────▶│     HSM     │
│                 │     │  (encrypt)   │     │  (key store)│
└─────────────────┘     └──────────────┘     └─────────────┘
                              │
                              ▼
                        Key never leaves HSM
                        (wrap/unwrap operations)
```

## Quick Start

### AWS CloudHSM

```python
from shield.hsm import CloudHSMKeyProvider
from shield import Shield

# Initialize HSM provider
hsm = CloudHSMKeyProvider(
    cluster_id='cluster-xxx',
    hsm_user='crypto_user',
    hsm_password='password'
)

# Create Shield with HSM-backed key
shield = Shield.with_key_provider(hsm, service='myapp.com')

# Encrypt/decrypt as normal
encrypted = shield.encrypt(b'secret data')
```

### HashiCorp Vault

```python
from shield.hsm import VaultKeyProvider
from shield import Shield

# Initialize Vault provider
vault = VaultKeyProvider(
    url='https://vault.example.com:8200',
    token='hvs.xxx',
    key_path='transit/keys/shield-key'
)

# Create Shield with Vault-backed key
shield = Shield.with_key_provider(vault, service='myapp.com')
```

### Azure Key Vault

```python
from shield.hsm import AzureKeyVaultProvider
from shield import Shield

# Initialize Azure provider
azure = AzureKeyVaultProvider(
    vault_url='https://myvault.vault.azure.net',
    key_name='shield-master-key'
)

shield = Shield.with_key_provider(azure, service='myapp.com')
```

## PKCS#11 Generic Interface

For any PKCS#11-compatible HSM:

```python
from shield.hsm import PKCS11KeyProvider

hsm = PKCS11KeyProvider(
    library_path='/usr/lib/softhsm/libsofthsm2.so',
    slot=0,
    pin='1234',
    key_label='shield-key'
)
```

## Key Rotation with HSM

```python
from shield.hsm import CloudHSMKeyProvider
from shield import KeyRotationManager

hsm = CloudHSMKeyProvider(...)

# Rotation manager handles key versioning
rotator = KeyRotationManager(
    key_provider=hsm,
    rotation_interval_days=90
)

# Automatically uses latest key version
shield = rotator.get_shield(service='myapp.com')
```

## Security Considerations

1. **Key Generation**: Always generate keys inside the HSM
2. **Key Export**: Disable key export in HSM policies
3. **Access Control**: Use IAM/RBAC to restrict HSM access
4. **Audit Logging**: Enable HSM audit logs
5. **Backup**: Use HSM-native backup mechanisms

## Performance

| Operation | Without HSM | With HSM (network) |
|-----------|-------------|-------------------|
| Key derivation | ~29ms | ~50-100ms |
| Encryption | ~160 MB/s | ~160 MB/s* |
| Decryption | ~160 MB/s | ~160 MB/s* |

*Encryption/decryption performance unchanged as HSM only wraps the key.

## Files in This Directory

- `aws_cloudhsm.py` - AWS CloudHSM example
- `azure_keyvault.py` - Azure Key Vault example
- `hashicorp_vault.py` - HashiCorp Vault example
- `yubihsm.py` - YubiHSM 2 example
- `pkcs11_generic.py` - Generic PKCS#11 example
