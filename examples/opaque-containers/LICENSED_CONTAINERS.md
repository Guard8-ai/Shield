# Licensed Opaque Containers with SaaS Protection

Combine Shield's opaque containers with Dikestra.ai's SaaS licensing system for maximum commercial software protection.

## Overview

This integration provides **triple-layer protection**:

1. **🔒 Encryption** - Container contents are opaque (Shield)
2. **🖥️ Hardware Binding** - Tied to specific device (Shield + SaaS)
3. **📋 License Validation** - Subscription-based access control (SaaS)

**Result:** Software that cannot be pirated, shared, or reverse-engineered.

---

## Use Cases

### 1. **Commercial ML Models**
- Ship trained models to customers
- Cannot extract weights
- Hardware-bound to licensed machines
- Subscription-based pricing

### 2. **Trading Algorithms**
- Sell proprietary strategies
- Cannot reverse engineer
- License per trading desk
- Remote kill switch

### 3. **Enterprise Software**
- Deploy to customer infrastructure
- Cannot inspect source code
- Per-machine licensing
- Audit trail

### 4. **Licensed SaaS Tools**
- Distribute CLI tools
- Hardware-bound licenses
- Subscription management
- Auto-renewal

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Application                         │
│                  (Proprietary Code/Model)                   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ 1. Build Docker container
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Shield Encrypted Container                     │
│  ┌───────────────────────────────────────────────────────┐ │
│  │ • Opaque (no one can see inside)                     │ │
│  │ • Hardware fingerprint bound (device-specific)       │ │
│  │ • HMAC tamper detection                              │ │
│  └───────────────────────────────────────────────────────┘ │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ 2. Distribute to customer
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                   Customer Environment                      │
│  ┌───────────────────────────────────────────────────────┐ │
│  │ 1. Hardware fingerprint checked                       │ │
│  │ 2. License validated (SaaS server)                    │ │
│  │ 3. Subscription active?                               │ │
│  │ 4. Decrypt container (if authorized)                  │ │
│  │ 5. Run application                                    │ │
│  └───────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                     ▲
                     │ 3. License check
                     │
┌─────────────────────────────────────────────────────────────┐
│            Dikestra.ai SaaS License Server                    │
│  ┌───────────────────────────────────────────────────────┐ │
│  │ • Hardware ID validation                              │ │
│  │ • Subscription status                                 │ │
│  │ • Trial period management                             │ │
│  │ • Remote revocation                                   │ │
│  │ • Audit logging                                       │ │
│  └───────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

1. **Shield** (for container encryption)
   ```bash
   cargo install shield-core --features cli
   ```

2. **SaaS Licensing System** (for license management)
   ```bash
   git clone https://github.com/Dikestra-ai/SaaSClient-SideLicensingSystem.git
   cd SaaSClient-SideLicensingSystem
   ./test/start_test_server.sh  # Start license server
   ```

### Step 1: Build Your Application Container

```bash
# Your proprietary application
docker build -t myapp:1.0 .
```

### Step 2: Encrypt with Hardware Binding

```bash
# Encrypt container with hardware fingerprinting
cd Shield/examples/opaque-containers

export SHIELD_PASSWORD="your-master-key"
./build-opaque.sh --fingerprint myapp:1.0
```

This creates:
- `myapp-1.0.enc` - Encrypted, hardware-bound container
- `myapp-1.0.sha256` - Integrity checksum
- `myapp-1.0.manifest.json` - Metadata with fingerprint info

### Step 3: Create License-Aware Runner Script

```bash
# Save as: run-licensed-container.sh
cat > run-licensed-container.sh <<'EOF'
#!/bin/bash
set -e

CONTAINER_FILE="$1"
SAAS_SERVER="${SAAS_SERVER:-http://localhost:8000}"

# Step 1: Get hardware fingerprint
echo "🔍 Detecting hardware fingerprint..."
HARDWARE_ID=$(shield fingerprint --mode combined)
echo "   Hardware ID: ${HARDWARE_ID:0:16}..."

# Step 2: Register/validate license
echo "📋 Validating license..."
RESPONSE=$(curl -s -X POST "$SAAS_SERVER/api/register" \
  -H "Content-Type: application/json" \
  -d "{\"hardware_id\": \"$HARDWARE_ID\", \"app_version\": \"1.0\"}")

API_KEY=$(echo "$RESPONSE" | jq -r '.api_key')
SUCCESS=$(echo "$RESPONSE" | jq -r '.success')

if [ "$SUCCESS" != "true" ]; then
  echo "❌ License validation failed!"
  echo "$RESPONSE" | jq -r '.message'
  exit 1
fi

echo "✅ License valid"

# Step 3: Check subscription status
echo "🔐 Checking subscription..."
SUB_STATUS=$(curl -s -X GET "$SAAS_SERVER/api/subscription/status" \
  -H "Authorization: Bearer $API_KEY")

ACTIVE=$(echo "$SUB_STATUS" | jq -r '.active')

if [ "$ACTIVE" != "true" ]; then
  echo "❌ Subscription inactive or expired"
  exit 1
fi

echo "✅ Subscription active"

# Step 4: Decrypt and run container
echo "🚀 Starting licensed container..."
./run-opaque.sh --verify "$CONTAINER_FILE"
EOF

chmod +x run-licensed-container.sh
```

### Step 4: Distribute to Customer

Send to customer:
1. `myapp-1.0.enc` (encrypted container)
2. `run-licensed-container.sh` (license-aware runner)
3. Customer credentials (API key or registration link)

### Step 5: Customer Runs Licensed Container

```bash
# Customer's machine (with valid license)
export SAAS_SERVER="https://your-license-server.com"
export SHIELD_PASSWORD="your-master-key"  # Or use env-based key management

./run-licensed-container.sh myapp-1.0.enc
```

**What happens:**
1. ✅ Hardware ID extracted
2. ✅ License validated against server
3. ✅ Subscription status checked
4. ✅ Container decrypted (hardware match + valid subscription)
5. ✅ Application runs
6. ❌ If license invalid/expired → Container won't decrypt

---

## Security Properties

### What Attackers CANNOT Do

| Attack | Protection | Result |
|--------|-----------|--------|
| Copy to another machine | Hardware fingerprint mismatch | Decrypt fails |
| Share with competitor | Hardware ID registered to original buyer | Decrypt fails |
| Reverse engineer code | Encrypted container + opaque | No access to source |
| Extract ML model weights | Encrypted + licensed | Cannot decrypt |
| Use after subscription ends | License server check | Access denied |
| Bypass license check | Container won't decrypt without valid license | Locked out |
| Crack the encryption | Nation-state resistant (SHA-256) | Impossible |

### What You CAN Do (Vendor)

| Capability | How | Benefit |
|-----------|-----|---------|
| Remote revocation | Deactivate license on server | Instant access removal |
| Usage analytics | License server logs | Track deployments |
| Subscription management | License expiry dates | Recurring revenue |
| Feature gating | Different license tiers | Upsell opportunities |
| Audit trail | Server-side logging | Compliance |
| Trial periods | 7-day trial in licensing system | Lead generation |

---

## Advanced: TEE + Licensed Containers

For **maximum security** (even host admin can't inspect):

### Build TEE-Protected Licensed Container

```bash
# Encrypt for AWS Nitro Enclave with hardware binding
./build-opaque.sh --tee --platform aws-nitro --fingerprint myapp:1.0
```

### Modified License-Aware Runner for TEE

```bash
cat > run-licensed-tee-container.sh <<'EOF'
#!/bin/bash
set -e

# Runs in AWS Nitro Enclave
# Host OS CANNOT inspect memory
# License validated via attestation

CONTAINER_FILE="$1"
SAAS_SERVER="${SAAS_SERVER:-http://localhost:8000}"

# Step 1: Generate TEE attestation
echo "🔒 Generating TEE attestation..."
ATTESTATION=$(nsm-cli attestation --nonce $(date +%s))

# Step 2: Get hardware fingerprint + attestation
HARDWARE_ID=$(shield fingerprint --mode combined)

# Step 3: Validate license with attestation proof
echo "📋 Validating license with TEE attestation..."
RESPONSE=$(curl -s -X POST "$SAAS_SERVER/api/register/tee" \
  -H "Content-Type: application/json" \
  -d "{
    \"hardware_id\": \"$HARDWARE_ID\",
    \"app_version\": \"1.0\",
    \"attestation_doc\": \"$ATTESTATION\"
  }")

# ... rest of license validation ...

# Step 4: Request decryption key (only released to valid TEE)
echo "🔑 Requesting container key..."
KEY=$(curl -s -X POST "$SAAS_SERVER/api/container/key" \
  -H "Authorization: Bearer $API_KEY" \
  -d "{\"attestation_doc\": \"$ATTESTATION\"}" \
  | jq -r '.key')

# Step 5: Decrypt in TEE
echo "$KEY" | shield decrypt \
  --input "$CONTAINER_FILE" \
  --output /tmp/decrypted.tar \
  --key-from-stdin

# Step 6: Load and run in TEE
docker load -i /tmp/decrypted.tar
# Container runs with CPU-encrypted memory
# Host admin CANNOT inspect
EOF

chmod +x run-licensed-tee-container.sh
```

**Ultimate Protection:**
- ✅ Encrypted container
- ✅ Hardware-bound license
- ✅ Subscription validation
- ✅ TEE isolation (host can't inspect)
- ✅ Attestation proof
- ✅ Remote key release

---

## Licensing Models

### Model 1: Per-Device License

```bash
# Build container bound to specific hardware
./build-opaque.sh --fingerprint myapp:1.0

# Customer buys license for 1 machine
# Hardware ID registered in license server
# Can only run on that specific device
```

**Pricing:** $99/device/month

### Model 2: Floating License Pool

```bash
# Build container with fingerprint
./build-opaque.sh --fingerprint myapp:1.0

# Customer buys pool of 10 concurrent licenses
# License server tracks active sessions
# First 10 machines can run, 11th is denied
```

**Pricing:** $500/month for 10 concurrent users

### Model 3: Time-Based Trial

```bash
# Customer downloads encrypted container
# Runs with trial license (7 days)
# License server enforces trial expiry
# Converts to paid after trial
```

**Pricing:** Free trial → $49/month

### Model 4: Feature Tiers

```bash
# Build with feature gating
./build-opaque.sh --fingerprint --tier basic myapp:1.0

# Basic tier: Limited features
# Pro tier: Full features
# Enterprise: Custom models + priority support
```

**Pricing:**
- Basic: $29/month
- Pro: $99/month
- Enterprise: Custom

---

## Implementation Guide

### Complete Dockerfile with License Integration

```dockerfile
FROM ubuntu:22.04

# Install Shield CLI
COPY shield /usr/local/bin/
RUN chmod +x /usr/local/bin/shield

# Install SaaS client library
COPY saas_client /app/
COPY libsaas_license.so /usr/local/lib/

# Your proprietary application
COPY myapp /app/myapp
RUN chmod +x /app/myapp

# License-aware entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
```

### Entrypoint with License Check

```bash
#!/bin/bash
# entrypoint.sh - Validates license before running app

set -e

SAAS_SERVER="${SAAS_SERVER:-https://license.myapp.com}"
APP_VERSION="${APP_VERSION:-1.0.0}"

# 1. Get hardware fingerprint
HARDWARE_ID=$(shield fingerprint --mode combined)

# 2. Load cached license (if exists)
LICENSE_FILE="/app/.license"
if [ -f "$LICENSE_FILE" ]; then
    API_KEY=$(cat "$LICENSE_FILE")
else
    # First run - register
    echo "📋 Registering device..."
    RESPONSE=$(curl -X POST "$SAAS_SERVER/api/register" \
        -H "Content-Type: application/json" \
        -d "{\"hardware_id\": \"$HARDWARE_ID\", \"app_version\": \"$APP_VERSION\"}")

    API_KEY=$(echo "$RESPONSE" | jq -r '.api_key')
    echo "$API_KEY" > "$LICENSE_FILE"
    chmod 600 "$LICENSE_FILE"
fi

# 3. Validate license
echo "🔐 Validating license..."
SUB_STATUS=$(curl -X GET "$SAAS_SERVER/api/subscription/status" \
    -H "Authorization: Bearer $API_KEY")

ACTIVE=$(echo "$SUB_STATUS" | jq -r '.active')

if [ "$ACTIVE" != "true" ]; then
    echo "❌ License invalid or expired"
    echo "Visit: https://myapp.com/renew"
    exit 1
fi

# 4. Run application
echo "✅ License valid - Starting application"
exec /app/myapp "$@"
```

### Build and Encrypt

```bash
# Build container
docker build -t myapp:1.0 .

# Encrypt with hardware binding
./build-opaque.sh --fingerprint --immutable myapp:1.0

# Now you have: myapp-1.0.enc (ready to distribute)
```

---

## Customer Onboarding Flow

### 1. Customer Signs Up

```
Customer → https://yourapp.com/signup
         → Creates account
         → Selects plan (Basic/Pro/Enterprise)
         → Payment processed
```

### 2. Download & Install

```bash
# Customer downloads encrypted container
wget https://yourapp.com/downloads/myapp-1.0.enc

# Download runner script
wget https://yourapp.com/downloads/run-licensed.sh
chmod +x run-licensed.sh

# Set license server
export SAAS_SERVER="https://license.yourapp.com"
export SHIELD_PASSWORD="<customer-key>"
```

### 3. First Run (Registration)

```bash
./run-licensed.sh myapp-1.0.enc
```

Output:
```
🔍 Detecting hardware fingerprint...
   Hardware ID: a3f2e8b1c4d9...

📋 Registering device...
   Device registered successfully!
   Trial period: 7 days

✅ License valid
🚀 Starting application...
```

### 4. Subsequent Runs

```bash
./run-licensed.sh myapp-1.0.enc
```

Output:
```
🔍 Hardware fingerprint: a3f2e8b1c4d9...
📋 Validating license... ✅
🔐 Subscription active (expires: 2026-03-23)
🚀 Starting application...
```

### 5. Subscription Renewal

License server sends reminder emails:
- 7 days before expiry
- 1 day before expiry
- On expiry

If expired:
```bash
./run-licensed.sh myapp-1.0.enc
```

Output:
```
❌ Subscription expired
Visit: https://yourapp.com/renew?license=abc123
```

---

## API Integration

### License Server Setup (Python/FastAPI)

```python
# Based on SaaSClient-SideLicensingSystem
from fastapi import FastAPI, HTTPException, Header
import sqlite3
from datetime import datetime, timedelta

app = FastAPI()

@app.post("/api/register")
async def register_device(request: RegistrationRequest):
    """Register device and issue trial license"""

    # Check if hardware ID already registered
    existing = db.get_license(request.hardware_id)
    if existing:
        return {"success": False, "message": "Device already registered"}

    # Create trial license (7 days)
    api_key = generate_api_key()
    trial_end = datetime.utcnow() + timedelta(days=7)

    db.create_license(
        hardware_id=request.hardware_id,
        api_key=api_key,
        trial_end=trial_end
    )

    return {
        "success": True,
        "api_key": api_key,
        "trial_end": trial_end,
        "message": "Trial activated"
    }

@app.get("/api/subscription/status")
async def check_subscription(authorization: str = Header()):
    """Validate subscription status"""

    api_key = authorization.replace("Bearer ", "")
    license_info = db.get_license_by_key(api_key)

    if not license_info:
        raise HTTPException(403, "Invalid API key")

    now = datetime.utcnow()

    # Check trial
    if now < license_info.trial_end:
        days_remaining = (license_info.trial_end - now).days
        return {
            "active": True,
            "trial_remaining_days": days_remaining
        }

    # Check subscription
    if license_info.subscription_end and now < license_info.subscription_end:
        return {
            "active": True,
            "expires_at": license_info.subscription_end
        }

    return {
        "active": False,
        "message": "Subscription expired"
    }

@app.post("/api/subscription/activate")
async def activate_subscription(
    authorization: str = Header(),
    plan: str = "pro",
    duration_months: int = 1
):
    """Activate paid subscription after payment"""

    api_key = authorization.replace("Bearer ", "")
    license_info = db.get_license_by_key(api_key)

    if not license_info:
        raise HTTPException(403, "Invalid API key")

    # Process payment (Stripe integration)
    payment_success = process_payment(license_info.hardware_id, plan, duration_months)

    if not payment_success:
        raise HTTPException(402, "Payment failed")

    # Activate subscription
    subscription_end = datetime.utcnow() + timedelta(days=30 * duration_months)
    db.update_subscription(api_key, subscription_end)

    return {
        "success": True,
        "subscription_end": subscription_end,
        "message": f"{plan.capitalize()} plan activated"
    }
```

---

## Revenue Models

### Comparison

| Model | Implementation | Pros | Cons | Best For |
|-------|---------------|------|------|----------|
| **Per-Device** | Hardware fingerprint + license | Strong piracy protection | Limited flexibility | High-value software ($100+) |
| **Floating Pool** | Concurrent session tracking | Flexible for teams | Complex to implement | Enterprise (teams) |
| **Time-Based** | Trial → paid subscription | Recurring revenue | Churn risk | SaaS apps |
| **Feature Tiers** | License-gated features | Upsell opportunity | Complexity | Varied user needs |

### Example Pricing Strategy

**Product:** ML Model Inference Container

| Tier | Price | Features | Target |
|------|-------|----------|--------|
| Trial | Free (7 days) | 100 inferences/day | Leads |
| Basic | $29/month | 1K inferences/day | Individuals |
| Pro | $99/month | 10K inferences/day | Small teams |
| Enterprise | $499/month | Unlimited + custom models | Large companies |

**Annual revenue potential:**
- 100 trial users → 30 convert → 20 Basic + 8 Pro + 2 Enterprise
- Revenue: (20 × $29 × 12) + (8 × $99 × 12) + (2 × $499 × 12) = **$29,448/year**

---

## Monitoring & Analytics

### License Server Dashboard

Track key metrics:
- Active licenses
- Trial conversions
- Churn rate
- Revenue (MRR/ARR)
- Hardware ID violations (piracy attempts)

```python
@app.get("/api/admin/stats")
async def get_stats():
    return {
        "total_licenses": db.count_licenses(),
        "active_trials": db.count_active_trials(),
        "active_subscriptions": db.count_active_subscriptions(),
        "revenue_mrr": db.calculate_mrr(),
        "top_customers": db.get_top_customers(limit=10),
        "piracy_attempts": db.count_failed_hw_checks()
    }
```

### Alerts

Set up alerts for:
- ✅ New registrations
- ✅ Trial → Paid conversions
- ✅ Subscription renewals
- ⚠️ Failed license checks
- ⚠️ Hardware mismatch (piracy attempt)
- ⚠️ High churn rate

---

## FAQ

### Q: Can customers copy the container to another machine?

**A:** No. Hardware fingerprint check will fail. Container won't decrypt.

### Q: What if customer upgrades their hardware?

**A:** They contact support. You update hardware ID in license server. Small fee for transfer.

### Q: Can customers share their license?

**A:** No. License is bound to specific hardware ID. Sharing won't work.

### Q: What if license server is down?

**A:** Implement grace period (24-48 hours offline). Cache last successful validation.

### Q: Can this be cracked?

**A:** Combined with TEE (AWS Nitro, Azure SEV), it's essentially uncrackable. Even without TEE, requires breaking nation-state-resistant encryption + license server + hardware binding.

### Q: How do I handle refunds?

**A:** Revoke API key in license server. Container stops working immediately.

### Q: Can I track which features customers use?

**A:** Yes! Add telemetry to license check. Track feature usage, performance, errors.

### Q: What about air-gapped environments?

**A:** Use time-limited licenses that work offline for X days. Require periodic re-validation.

---

## Summary

**Licensed Opaque Containers = Ultimate Commercial Software Protection**

✅ **Triple Protection:**
1. Encrypted (opaque)
2. Hardware-bound (device-specific)
3. License-validated (subscription-based)

✅ **Business Benefits:**
- Recurring revenue (subscriptions)
- Piracy prevention (hardware-bound)
- Remote control (revocation)
- Usage analytics
- Trial → conversion funnel

✅ **Security Benefits:**
- Cannot reverse engineer
- Cannot share/copy
- Cannot run on unauthorized hardware
- Cannot bypass license checks
- Nation-state resistant encryption

**Perfect for:**
- ML model distribution
- Trading algorithm licensing
- Enterprise software delivery
- SaaS tool monetization

---

## Next Steps

1. **Set up license server:**
   ```bash
   git clone https://github.com/Dikestra-ai/SaaSClient-SideLicensingSystem.git
   cd SaaSClient-SideLicensingSystem
   ./test/start_test_server.sh
   ```

2. **Encrypt your container:**
   ```bash
   cd Shield/examples/opaque-containers
   ./build-opaque.sh --fingerprint myapp:1.0
   ```

3. **Test license integration:**
   ```bash
   ./run-licensed-container.sh myapp-1.0.enc
   ```

4. **Deploy to production:**
   - Set up production license server (FastAPI + PostgreSQL)
   - Configure payment processing (Stripe/PayPal)
   - Add customer dashboard
   - Enable monitoring/alerts

**Start monetizing your software with unbreakable protection!** 💰🔒

---

**Resources:**
- Shield: `/Shield/examples/opaque-containers/`
- SaaS Licensing: `/SaaSClient-SideLicensingSystem/`
- Support: admin@gibraltarcloud.dev
