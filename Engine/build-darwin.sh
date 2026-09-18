#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build/macos-arm64"
mkdir -p "$BUILD_DIR"

cd "$SCRIPT_DIR/libgocryptfs"

GO_BIN="$(which go || echo "/opt/local/bin/go")"

echo "Building darwin arm64 c-archive using $GO_BIN..."
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 "$GO_BIN" build \
  -buildmode=c-archive \
  -trimpath \
  -ldflags="-s -w" \
  -tags without_openssl \
  -o "$BUILD_DIR/libgocryptfs.a" .

mkdir -p "$SCRIPT_DIR/build"
cp "$BUILD_DIR/libgocryptfs.a" "$SCRIPT_DIR/build/libgocryptfs.a"
cp "$BUILD_DIR/libgocryptfs.h" "$SCRIPT_DIR/build/libgocryptfs.h"

echo "Successfully built $BUILD_DIR/libgocryptfs.a"
