# Opaque Container Demo

Quick demonstration of Shield's opaque container capabilities.

## Try It Yourself

### Step 1: Build the example container

```bash
cd examples/opaque-containers
docker build -f Dockerfile.example -t secret-demo:1.0 .
```

### Step 2: Test it works (plaintext)

```bash
docker run --rm secret-demo:1.0
```

You'll see the "secret algorithm" output.

### Step 3: Encrypt the container

```bash
export SHIELD_PASSWORD="my-secure-password-123"
./build-opaque.sh secret-demo:1.0
```

This creates:
- `secret-demo-1.0.enc` (encrypted, opaque)
- `secret-demo-1.0.sha256` (integrity)
- `secret-demo-1.0.manifest.json` (metadata)

### Step 4: Try to inspect it (will fail)

```bash
# This won't work - it's encrypted!
docker load -i secret-demo-1.0.enc
# Error: file is encrypted

# Try to see what's inside
strings secret-demo-1.0.enc | grep "SECRET"
# Nothing! It's opaque.
```

### Step 5: Run the encrypted container

```bash
./run-opaque.sh secret-demo-1.0.enc
# Enter password when prompted (or use SHIELD_PASSWORD env var)
```

The container decrypts, runs, and plaintext is deleted.

## What Just Happened?

1. ✅ You built a container with "secret" code
2. ✅ Encrypted it with Shield (opaque blob)
3. ✅ Verified no one can inspect it
4. ✅ Ran it in authorized environment
5. ✅ Plaintext auto-deleted after execution

## Real-World Scenario

Imagine `secret-demo:1.0` is actually:
- Your profitable trading algorithm
- Your trained ML model (worth $1M)
- Your proprietary analytics engine

**You can now:**
- ✅ Ship to customers (they can't extract the algorithm)
- ✅ Deploy to cloud (AWS/GCP/Azure can't see inside)
- ✅ Distribute publicly (competitors can't reverse engineer)
- ✅ License by hardware (add --fingerprint flag)

**Others can only:**
- ❌ Run it (if they have password)
- ✅ Delete it

## Advanced: Immutable Container

```bash
# Build with immutability enforced
./build-opaque.sh --immutable secret-demo:1.0

# Run with hardened security
./run-opaque.sh --immutable secret-demo-1.0.enc
```

Now the container:
- Cannot be modified at runtime (read-only FS)
- Cannot escalate privileges
- Cannot use dangerous syscalls

## Next: TEE Protection

For MAXIMUM security (even host admin can't inspect):

```bash
# See: build-tee-container.sh
./build-tee-container.sh --platform aws-nitro secret-demo:1.0
```

This runs in AWS Nitro Enclave where:
- CPU encrypts memory
- Host OS cannot inspect
- Even AWS cannot see inside
- Cryptographic proof of security

---

**You now have a truly opaque container!** 🔒
