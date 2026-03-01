---
id: backend-002
title: Implement NSM attestation in NitroAttestationProvider
status: done
priority: high
tags:
- confidential-computing
- nitro
dependencies:
- backend-001
assignee: claude
created: 2026-03-01T09:07:29.040873935Z
estimate: 2h
complexity: 7
area: backend
---

# Implement NSM attestation in NitroAttestationProvider

## Causation Chain
```
NitroAttestationProvider::generate_evidence()
  → checks /dev/nsm exists
  → calls nsm_get_attestation()        ← PLACEHOLDER: returns error
  → should: open /dev/nsm, send ioctl, return COSE Sign1 document

NitroVsockClient::send()              ← PLACEHOLDER: returns MissingDependency error
  → should: open AF_VSOCK socket, connect to CID:port, send/recv data

NitroVsockServer::start()             ← PLACEHOLDER: returns MissingDependency error
  → should: bind AF_VSOCK socket, accept connections, call handler
```

## Pre-flight Checks
- [x] `src/confidential/nitro.rs:263-275` — `nsm_get_attestation()` placeholder
- [x] `src/confidential/nitro.rs:316-328` — `NitroVsockClient::send()` placeholder
- [x] `src/confidential/nitro.rs:346-361` — `NitroVsockServer::start()` placeholder

## Context
Three functions in `nitro.rs` return placeholder errors instead of real implementations.
The NSM (Nitro Secure Module) communicates via `/dev/nsm` ioctl calls using CBOR-encoded
requests/responses. vsock uses Linux's AF_VSOCK address family for enclave-host communication.

## Tasks
- [ ] Implement `nsm_get_attestation()` using `/dev/nsm` ioctl with CBOR request
  - Build CBOR attestation request: `{"Attestation": {"user_data": ..., "nonce": ..., "public_key": ...}}`
  - Send via `ioctl(fd, NSM_IOCTL_REQUEST, &request)` — ioctl number 0
  - Parse CBOR response to extract COSE Sign1 attestation document
  - ciborium is already a dependency for CBOR serialization
- [ ] Implement `NitroVsockClient::send()` using raw AF_VSOCK socket
  - Use `libc::socket(AF_VSOCK, SOCK_STREAM, 0)` + `libc::connect()`
  - AF_VSOCK = 40, sockaddr_vm struct with svm_cid and svm_port
  - Send data length prefix (4 bytes LE) + data, read response same way
- [ ] Implement `NitroVsockServer::start()` using AF_VSOCK bind+listen+accept
  - Use `libc::bind()` + `libc::listen()` + `libc::accept()`
  - CID_ANY = u32::MAX for binding
  - Accept loop: read request, call handler, write response
- [ ] Remove all "placeholder" and "For now" comments
- [ ] `cargo test --features confidential` passes
- [ ] `cargo clippy --tests --features confidential -- -D warnings` passes

## Acceptance Criteria
- No placeholder errors in nitro.rs
- No "For now" or "not yet implemented" comments
- NSM ioctl uses correct request format (CBOR via ciborium)
- vsock uses correct AF_VSOCK protocol (libc raw sockets)
- Graceful error handling when not in enclave

## Notes
- NSM ioctl interface: fd = open("/dev/nsm"), ioctl(fd, 0, &nsm_message)
- nsm_message struct: request_ptr, request_len, response_ptr, response_len
- AF_VSOCK = 40 on Linux, VMADDR_CID_ANY = 0xFFFFFFFF, VMADDR_CID_HOST = 2
- All socket operations use `unsafe` libc calls — this is expected for low-level kernel interfaces
- ciborium already in Cargo.toml (confidential feature)
- No external crate dependencies needed — use libc directly

---
**Session Handoff** (fill when done):
- Changed: [files/functions modified]
- Causality: [what triggers what]
- Verify: [how to test this works]
- Next: [context for dependent tasks]