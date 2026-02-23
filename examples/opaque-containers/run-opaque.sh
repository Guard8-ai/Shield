#!/usr/bin/env bash
#
# run-opaque.sh - Decrypt and run opaque Docker container
#
# Usage:
#   ./run-opaque.sh myapp-1.0.enc
#   ./run-opaque.sh --immutable --verify myapp-1.0.enc
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
VERIFY=true
KEEP_PLAINTEXT=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --immutable)
            IMMUTABLE=true
            shift
            ;;
        --verify)
            VERIFY=true
            shift
            ;;
        --no-verify)
            VERIFY=false
            shift
            ;;
        --keep-plaintext)
            KEEP_PLAINTEXT=true
            shift
            ;;
        -*)
            echo "Unknown option: $1"
            exit 1
            ;;
        *)
            ENCRYPTED_FILE="$1"
            shift
            ;;
    esac
done

if [ -z "$ENCRYPTED_FILE" ]; then
    echo -e "${RED}Error: No encrypted container specified${NC}"
    echo "Usage: $0 [OPTIONS] ENCRYPTED_CONTAINER.enc"
    echo ""
    echo "Options:"
    echo "  --immutable      Run with read-only filesystem"
    echo "  --verify         Verify integrity (default)"
    echo "  --no-verify      Skip verification"
    echo "  --keep-plaintext Keep decrypted tar (for debugging)"
    exit 1
fi

if [ ! -f "$ENCRYPTED_FILE" ]; then
    echo -e "${RED}Error: File not found: $ENCRYPTED_FILE${NC}"
    exit 1
fi

# Extract base name
BASE_NAME=$(basename "$ENCRYPTED_FILE" .enc)
MANIFEST_FILE="${BASE_NAME}.manifest.json"
SHA256_FILE="${BASE_NAME}.sha256"

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   Shield Opaque Container Runner${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Encrypted file: ${GREEN}$ENCRYPTED_FILE${NC}"
echo -e "  Verify:         $([ "$VERIFY" = true ] && echo -e "${GREEN}Yes${NC}" || echo -e "${YELLOW}No${NC}")"
echo -e "  Immutable:      $([ "$IMMUTABLE" = true ] && echo -e "${GREEN}Yes${NC}" || echo -e "${YELLOW}No${NC}")"
echo ""

# Create temp directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

# Step 1: Verify integrity
if [ "$VERIFY" = true ] && [ -f "$SHA256_FILE" ]; then
    echo -e "${BLUE}[1/4]${NC} Verifying integrity..."
    EXPECTED_SHA=$(cat "$SHA256_FILE")
    ACTUAL_SHA=$(sha256sum "$ENCRYPTED_FILE" | cut -d' ' -f1)

    if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
        echo -e "${RED}      ✗ INTEGRITY FAILURE${NC}"
        echo "      Expected: $EXPECTED_SHA"
        echo "      Actual:   $ACTUAL_SHA"
        echo ""
        echo -e "${RED}WARNING: Container may have been tampered with!${NC}"
        exit 1
    fi
    echo -e "      ${GREEN}✓${NC} SHA-256 verified: ${ACTUAL_SHA:0:16}..."
elif [ "$VERIFY" = true ]; then
    echo -e "${YELLOW}[1/4] Warning: No SHA-256 file found, skipping pre-check${NC}"
else
    echo -e "${YELLOW}[1/4] Skipping integrity verification (--no-verify)${NC}"
fi

# Step 2: Decrypt with Shield
echo -e "${BLUE}[2/4]${NC} Decrypting container..."

if [ -n "$SHIELD_PASSWORD" ]; then
    echo "      Using password from SHIELD_PASSWORD environment variable"
    echo "$SHIELD_PASSWORD" | shield decrypt \
        --input "$ENCRYPTED_FILE" \
        --output "${TEMP_DIR}/${BASE_NAME}.tar" \
        --password-from-stdin
else
    echo -e "${YELLOW}      Enter password to decrypt container:${NC}"
    shield decrypt \
        --input "$ENCRYPTED_FILE" \
        --output "${TEMP_DIR}/${BASE_NAME}.tar"
fi

if [ $? -ne 0 ]; then
    echo -e "${RED}      ✗ Decryption failed${NC}"
    echo ""
    echo "Possible reasons:"
    echo "  - Wrong password"
    echo "  - Container was tampered (HMAC authentication failed)"
    echo "  - Wrong hardware fingerprint (if container is device-bound)"
    exit 1
fi

SIZE=$(du -h "${TEMP_DIR}/${BASE_NAME}.tar" | cut -f1)
echo -e "      ${GREEN}✓${NC} Decrypted ${SIZE} container"

# Step 3: Load into Docker
echo -e "${BLUE}[3/4]${NC} Loading container into Docker..."
if ! docker load -i "${TEMP_DIR}/${BASE_NAME}.tar"; then
    echo -e "${RED}      ✗ Failed to load Docker image${NC}"
    exit 1
fi

# Extract image name from docker load output (or manifest)
if [ -f "$MANIFEST_FILE" ]; then
    IMAGE_NAME=$(jq -r '.name' "$MANIFEST_FILE")
    IMAGE_VERSION=$(jq -r '.version' "$MANIFEST_FILE")
    IMAGE_TAG="${IMAGE_NAME}:${IMAGE_VERSION}"
    IS_IMMUTABLE=$(jq -r '.immutable' "$MANIFEST_FILE")

    if [ "$IS_IMMUTABLE" = "true" ]; then
        IMMUTABLE=true
        echo -e "      ${YELLOW}Note: Manifest indicates immutable container${NC}"
    fi
else
    # Try to extract from docker images
    IMAGE_TAG=$(docker images --format "{{.Repository}}:{{.Tag}}" | head -1)
    echo -e "      ${YELLOW}Warning: No manifest found, using: $IMAGE_TAG${NC}"
fi

echo -e "      ${GREEN}✓${NC} Loaded as $IMAGE_TAG"

# Step 4: Run container
echo -e "${BLUE}[4/4]${NC} Running container..."

RUN_OPTS=""
if [ "$IMMUTABLE" = true ]; then
    echo "      Using immutable configuration:"
    echo "        - Read-only filesystem"
    echo "        - No new privileges"
    echo "        - All capabilities dropped"
    echo "        - Limited /tmp (100MB, noexec)"

    RUN_OPTS="--read-only \
              --security-opt=no-new-privileges \
              --cap-drop=ALL \
              --tmpfs /tmp:rw,noexec,nosuid,size=100m"
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   Starting Container${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Run the container
docker run --rm $RUN_OPTS "$IMAGE_TAG"

EXIT_CODE=$?

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   Container Stopped (exit code: $EXIT_CODE)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Cleanup
if [ "$KEEP_PLAINTEXT" = false ]; then
    echo "Cleaning up plaintext artifacts..."
    echo -e "  ${GREEN}✓${NC} Deleted decrypted tar from temp directory"
    # TEMP_DIR will be deleted by trap
else
    echo -e "${YELLOW}Plaintext kept at: ${TEMP_DIR}/${BASE_NAME}.tar${NC}"
    # Disable trap so directory isn't deleted
    trap - EXIT
fi

echo ""
echo "Security summary:"
echo -e "  ${GREEN}✓${NC} Container was encrypted during storage"
echo -e "  ${GREEN}✓${NC} Decryption required correct password"
echo -e "  ${GREEN}✓${NC} HMAC authentication verified integrity"
if [ "$IMMUTABLE" = true ]; then
    echo -e "  ${GREEN}✓${NC} Container ran with immutable filesystem"
fi
if [ "$KEEP_PLAINTEXT" = false ]; then
    echo -e "  ${GREEN}✓${NC} Plaintext deleted after execution"
fi
echo ""

exit $EXIT_CODE
