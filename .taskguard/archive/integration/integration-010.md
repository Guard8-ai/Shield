---
id: integration-010
title: FastAPI Shield middleware for Confidential Computing
status: done
priority: high
tags:
- integration
- confidential-computing
- fastapi
dependencies:
- backend-021
- api-001
assignee: developer
created: 2026-01-16T11:48:45.373772283Z
estimate: 1d
complexity: 6
area: integration
---

# FastAPI Shield middleware for Confidential Computing

## Context
Shield already has comprehensive FastAPI integration (`shield.integrations.fastapi`). This task extends it for confidential computing environments, adding attestation verification and TEE-aware key management.

## Existing Components (Already Implemented)
- `ShieldMiddleware` - Encrypts all JSON responses automatically
- `shield_protected` decorator - Per-endpoint encryption
- `ShieldAPIKeyAuth` - API key authentication with Shield
- `ShieldTokenAuth` - Bearer token authentication
- `RateLimiter` / `TokenBucket` - Rate limiting with encrypted state
- `APIProtector` - IP filtering + rate limiting + audit logging

## Architecture
```
┌─────────────────────────────────────────────────┐
│        Confidential Computing Environment       │
│  ┌─────────────────────────────────────────┐    │
│  │  FastAPI + Shield Middleware            │    │
│  │  - Auto-decrypt requests               │    │
│  │  - Auto-encrypt responses              │    │
│  │  - Attestation-gated endpoints         │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
        ↑ Attestation verification
┌───────┴───────┐
│  TEE          │ → AWS Nitro / GCP SEV / Azure MAA
│  Attestation  │ → Verify client & server TEE
└───────────────┘
```

## Tasks
- [ ] Add `AttestationMiddleware` for verifying client attestation
- [ ] Create `TEEKeyManager` for attestation-gated key release
- [ ] Add `@requires_attestation` decorator for protected endpoints
- [ ] Implement mutual attestation (server proves TEE to client)
- [ ] Create health endpoint returning TEE attestation report
- [ ] Add example: FastAPI in AWS Nitro with attestation
- [ ] Add example: FastAPI in GCP Confidential VM
- [ ] Add example: FastAPI in Azure Confidential Container
- [ ] Write deployment guide for each cloud provider

## New Components to Add

### 1. AttestationMiddleware
```python
app.add_middleware(
    AttestationMiddleware,
    tee_type="nitro",  # or "sev", "sgx", "maa"
    require_client_attestation=True,
)
```

### 2. TEEKeyManager
```python
key_manager = TEEKeyManager(
    password="secret",
    service="api.example.com",
    attestation_provider="aws_nitro",
)
# Keys released only after attestation
key = await key_manager.get_key(attestation_doc)
```

### 3. Attestation Decorator
```python
@app.get("/secure")
@requires_attestation(tee_type="nitro")
async def secure_endpoint():
    return {"data": "only accessible from attested TEE"}
```

## Dependencies
- Existing: `shield.integrations.fastapi`
- New: Cloud-specific attestation SDKs (per provider)

## Acceptance Criteria
- [ ] FastAPI app runs in all 4 TEE environments
- [ ] Client attestation verified before processing requests
- [ ] Server provides attestation proof to clients
- [ ] Keys released only to attested environments
- [ ] Existing Shield middleware works unmodified in TEEs

## Notes
- Existing Shield middleware works transparently in TEEs
- This task adds attestation awareness, not basic encryption
- Each cloud provider has different attestation mechanisms
- Consider abstracting providers behind common interface

---
**Session Handoff** (completed 2026-01-16):
- Changed: `python/shield/integrations/confidential/middleware.py`, `python/shield/integrations/__init__.py`
- Causality: `AttestationMiddleware` intercepts requests → calls `provider.verify()` → sets `request.state.attestation`
- Verify: Import from `shield.integrations`, use `@requires_attestation` decorator
- Next: Add more examples, test mutual attestation between services
