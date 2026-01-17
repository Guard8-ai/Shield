# Shield Confidential Computing Examples

This directory contains examples for running Shield-protected applications
in various Confidential Computing environments with hardware-backed attestation.

## Supported Platforms

| Platform | TEE Technology | Provider Module |
|----------|---------------|-----------------|
| AWS Nitro Enclaves | Nitro Security Module | `NitroAttestationProvider` |
| GCP Confidential VMs | AMD SEV-SNP | `SEVAttestationProvider` |
| Azure Confidential Containers | Intel SGX / AMD SEV-SNP | `MAAAttestationProvider` |
| Intel SGX (Gramine/Occlum) | Intel SGX | `SGXAttestationProvider` |

## Quick Start

### Installation

```bash
pip install shield-crypto
# For cloud-specific features:
pip install boto3  # AWS
pip install google-cloud-secret-manager  # GCP
pip install azure-identity azure-keyvault-keys  # Azure
pip install cbor2  # For Nitro attestation parsing
```

### Basic Usage

```python
from shield.integrations.confidential import (
    AttestationMiddleware,
    NitroAttestationProvider,  # or SEV, MAA, SGX
    requires_attestation,
    TEEKeyManager,
)
from fastapi import FastAPI

app = FastAPI()

# Choose provider for your platform
provider = NitroAttestationProvider()

# Add attestation middleware
app.add_middleware(
    AttestationMiddleware,
    provider=provider,
    require_client_attestation=True,
)

# Protect endpoints
@app.get("/secure")
@requires_attestation(provider=provider)
async def secure_endpoint(request):
    attestation = request.state.attestation
    return {"verified": attestation.verified}
```

## Examples

### AWS Nitro Enclaves
- `aws-nitro/fastapi_enclave.py` - FastAPI running inside enclave
- `aws-nitro/parent_instance.py` - Parent EC2 instance proxy

### GCP Confidential VMs
- `gcp-sev/fastapi_confidential.py` - FastAPI on Confidential VM

### Azure Confidential Containers
- `azure-acc/fastapi_confidential.py` - FastAPI in AKS confcom

### Intel SGX
- `intel-sgx/fastapi_enclave.py` - FastAPI via Gramine

## Key Concepts

### Attestation
Hardware-signed proof that code is running in a genuine TEE:
- **AWS Nitro**: COSE-signed document with PCR measurements
- **GCP SEV**: vTPM + SEV-SNP measurements in JWT
- **Azure MAA**: Microsoft-signed JWT with TEE evidence
- **Intel SGX**: DCAP quote with MRENCLAVE/MRSIGNER

### Key Release
Keys only released after attestation verification:
```python
key_manager = TEEKeyManager(
    password="secret",
    service="my-service",
    provider=provider,
)
key = await key_manager.get_key(attestation_evidence)
```

### Sealed Storage (SGX)
Persist secrets encrypted to enclave identity:
```python
storage = SealedStorage(seal_to="mrenclave")
await storage.store("my_key", secret_data)
data = await storage.load("my_key")
```

## Security Model

1. **Memory Encryption**: TEE hardware encrypts memory
2. **Attestation**: Cryptographic proof of TEE integrity
3. **Key Binding**: Keys tied to specific TEE measurements
4. **Mutual Attestation**: Both client and server prove TEE status

## Deployment Guides

### AWS Nitro
```bash
# Build enclave image
nitro-cli build-enclave --docker-uri shield-api:latest --output-file shield-api.eif

# Run enclave
nitro-cli run-enclave --eif-path shield-api.eif --cpu-count 2 --memory 512
```

### GCP Confidential VMs
```bash
gcloud compute instances create shield-api \
    --machine-type n2d-standard-2 \
    --zone us-central1-a \
    --confidential-compute-type SEV_SNP \
    --image-family cos-stable \
    --image-project cos-cloud
```

### Azure Confidential Containers
```bash
# Enable confcom on AKS
az aks enable-addons --addons confcom --name myCluster --resource-group myRG

# Deploy with confidential node pool
kubectl apply -f deployment-confidential.yaml
```

### Intel SGX (Gramine)
```bash
# Generate and sign manifest
gramine-manifest shield.manifest.template > shield.manifest
gramine-sgx-sign --manifest shield.manifest --output shield.manifest.sgx

# Run in SGX enclave
gramine-sgx ./shield
```
