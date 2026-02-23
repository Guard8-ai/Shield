#!/usr/bin/env bash
#
# build-opaque.sh - Build encrypted, opaque Docker container
#
# Usage:
#   ./build-opaque.sh myapp:1.0
#   ./build-opaque.sh --immutable --fingerprint myapp:1.0
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Options
IMMUTABLE=false
FINGERPRINT=false
TEE=false
PLATFORM=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --immutable)
            IMMUTABLE=true
            shift
            ;;
        --fingerprint)
            FINGERPRINT=true
            shift
            ;;
        --tee)
            TEE=true
            shift
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        -*)
            echo "Unknown option: $1"
            exit 1
            ;;
        *)
            IMAGE_TAG="$1"
            shift
            ;;
    esac
done

if [ -z "$IMAGE_TAG" ]; then
    echo -e "${RED}Error: No image tag specified${NC}"
    echo "Usage: $0 [OPTIONS] IMAGE:TAG"
    echo ""
    echo "Options:"
    echo "  --immutable       Enable read-only filesystem protection"
    echo "  --fingerprint     Bind to hardware fingerprint"
    echo "  --tee             Prepare for TEE deployment"
    echo "  --platform PLATFORM  TEE platform (aws-nitro, azure-sev, gcp-sev, intel-sgx)"
    exit 1
fi

# Extract name and version
IMAGE_NAME=$(echo "$IMAGE_TAG" | cut -d: -f1)
IMAGE_VERSION=$(echo "$IMAGE_TAG" | cut -d: -f2)
OUTPUT_NAME="${IMAGE_NAME//\//-}-${IMAGE_VERSION}"

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   Shield Opaque Container Builder${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Image:        ${GREEN}$IMAGE_TAG${NC}"
echo -e "  Output:       ${GREEN}$OUTPUT_NAME.enc${NC}"
echo -e "  Immutable:    $([ "$IMMUTABLE" = true ] && echo -e "${GREEN}Yes${NC}" || echo -e "${YELLOW}No${NC}")"
echo -e "  Fingerprint:  $([ "$FINGERPRINT" = true ] && echo -e "${GREEN}Yes${NC}" || echo -e "${YELLOW}No${NC}")"
echo -e "  TEE:          $([ "$TEE" = true ] && echo -e "${GREEN}Yes ($PLATFORM)${NC}" || echo -e "${YELLOW}No${NC}")"
echo ""

# Step 1: Save container to tar
echo -e "${BLUE}[1/5]${NC} Saving Docker image to tar..."
if ! docker save "$IMAGE_TAG" -o "${OUTPUT_NAME}.tar"; then
    echo -e "${RED}Error: Failed to save Docker image${NC}"
    echo "Make sure the image exists: docker images | grep $IMAGE_NAME"
    exit 1
fi
SIZE=$(du -h "${OUTPUT_NAME}.tar" | cut -f1)
echo -e "      ${GREEN}✓${NC} Saved ${SIZE} tar archive"

# Step 2: Encrypt with Shield
echo -e "${BLUE}[2/5]${NC} Encrypting container with Shield..."

ENCRYPT_CMD="shield encrypt"
ENCRYPT_OPTS=""

if [ "$FINGERPRINT" = true ]; then
    ENCRYPT_OPTS="$ENCRYPT_OPTS --fingerprint combined"
    echo "      Using hardware fingerprinting (device-bound)"
fi

if [ -n "$SHIELD_PASSWORD" ]; then
    echo "      Using password from SHIELD_PASSWORD environment variable"
else
    echo -e "${YELLOW}      Enter password to encrypt container:${NC}"
fi

# Encrypt the tar file
if [ -n "$SHIELD_PASSWORD" ]; then
    echo "$SHIELD_PASSWORD" | shield encrypt \
        --input "${OUTPUT_NAME}.tar" \
        --output "${OUTPUT_NAME}.enc" \
        --service "${IMAGE_NAME}-container" \
        --password-from-stdin \
        $ENCRYPT_OPTS
else
    shield encrypt \
        --input "${OUTPUT_NAME}.tar" \
        --output "${OUTPUT_NAME}.enc" \
        --service "${IMAGE_NAME}-container" \
        $ENCRYPT_OPTS
fi

echo -e "      ${GREEN}✓${NC} Encrypted to ${OUTPUT_NAME}.enc"

# Step 3: Generate signature
echo -e "${BLUE}[3/5]${NC} Generating HMAC signature..."
# The signature is embedded in the Shield format (HMAC)
# For additional verification, compute SHA-256 of encrypted file
SHA256=$(sha256sum "${OUTPUT_NAME}.enc" | cut -d' ' -f1)
echo "$SHA256" > "${OUTPUT_NAME}.sha256"
echo -e "      ${GREEN}✓${NC} SHA-256: ${SHA256:0:16}..."

# Step 4: Create manifest
echo -e "${BLUE}[4/5]${NC} Creating manifest..."
cat > "${OUTPUT_NAME}.manifest.json" <<MANIFEST
{
  "name": "$IMAGE_NAME",
  "version": "$IMAGE_VERSION",
  "encrypted": true,
  "immutable": $IMMUTABLE,
  "fingerprint": $FINGERPRINT,
  "tee": $TEE,
  "platform": "$PLATFORM",
  "sha256": "$SHA256",
  "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "encrypted_size": $(stat -f%z "${OUTPUT_NAME}.enc" 2>/dev/null || stat -c%s "${OUTPUT_NAME}.enc"),
  "runtime": "docker",
  "shield_version": "2.1.0"
}
MANIFEST
echo -e "      ${GREEN}✓${NC} Created ${OUTPUT_NAME}.manifest.json"

# Step 5: Cleanup plaintext
echo -e "${BLUE}[5/5]${NC} Securing plaintext artifacts..."
echo "      Deleting plaintext tar file..."
rm -f "${OUTPUT_NAME}.tar"
echo -e "      ${GREEN}✓${NC} Deleted ${OUTPUT_NAME}.tar"

if [ "$IMMUTABLE" = true ]; then
    echo "      Removing source Docker image from local registry..."
    docker rmi "$IMAGE_TAG" 2>/dev/null || true
    echo -e "      ${GREEN}✓${NC} Removed $IMAGE_TAG from docker images"
fi

# Summary
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   ✓ Opaque Container Created Successfully${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "Files created:"
echo -e "  ${GREEN}${OUTPUT_NAME}.enc${NC}           (encrypted container - safe to distribute)"
echo -e "  ${GREEN}${OUTPUT_NAME}.sha256${NC}        (integrity checksum)"
echo -e "  ${GREEN}${OUTPUT_NAME}.manifest.json${NC} (metadata)"
echo ""
echo "What you can do with these files:"
echo -e "  ${GREEN}✓${NC} Distribute ${OUTPUT_NAME}.enc publicly (contents are opaque)"
echo -e "  ${GREEN}✓${NC} Store in untrusted locations (cloud storage, etc.)"
echo -e "  ${GREEN}✓${NC} Share with customers (they cannot reverse engineer)"
echo ""
echo "What others CANNOT do:"
echo -e "  ${RED}✗${NC} Inspect container contents (encrypted)"
echo -e "  ${RED}✗${NC} Extract files or code (HMAC-protected)"
echo -e "  ${RED}✗${NC} Reverse engineer algorithms (opaque blob)"
echo -e "  ${RED}✗${NC} Modify container (authentication fails)"
echo ""
echo "To run this container:"
echo -e "  ${BLUE}./run-opaque.sh ${OUTPUT_NAME}.enc${NC}"
echo ""

if [ "$TEE" = true ]; then
    echo -e "${YELLOW}Note: TEE deployment requires additional setup.${NC}"
    echo "See: ./build-tee-container.sh --help"
    echo ""
fi
