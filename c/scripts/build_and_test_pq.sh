#!/usr/bin/env bash
# Build liboqs (ML-KEM-768) if needed, then compile and run the Shield C
# post-quantum hybrid-KEX conformance test against tests/pq_kex_vectors.json.
#
# Requires: a C compiler, cmake, ninja, OpenSSL >= 3.0 dev headers, git.
# Targets POSIX hosts (Linux/macOS). On Debian/Ubuntu:
#   sudo apt-get install -y build-essential cmake ninja-build pkg-config libssl-dev git
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # the c/ directory
REPO="$(cd "$HERE/.." && pwd)"
PREFIX="${OQS_PREFIX:-/usr/local}"

# Build liboqs only if it isn't already installed.
if ! { [ -f "$PREFIX/include/oqs/oqs.h" ] && ls "$PREFIX"/lib/liboqs.* >/dev/null 2>&1; }; then
  echo "==> building liboqs (ML-KEM-768) into $PREFIX"
  tmp="$(mktemp -d)"
  git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git "$tmp/liboqs"
  cmake -GNinja -S "$tmp/liboqs" -B "$tmp/liboqs/build" \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_MINIMAL_BUILD="KEM_ml_kem_768" \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DCMAKE_INSTALL_PREFIX="$PREFIX"
  ninja -C "$tmp/liboqs/build"
  ${SUDO:-} ninja -C "$tmp/liboqs/build" install
  ${SUDO:-} ldconfig 2>/dev/null || true
fi

echo "==> compiling C PQ test"
cc -O2 -Wall -Wextra -I "$HERE/include" \
  "$HERE/src/pqhybrid.c" "$HERE/tests/test_pqhybrid.c" \
  -I "$PREFIX/include" -L "$PREFIX/lib" -loqs -lcrypto \
  -o "$HERE/test_pqhybrid"

echo "==> running C PQ conformance test"
LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}" \
  "$HERE/test_pqhybrid" "$REPO/tests/pq_kex_vectors.json"
