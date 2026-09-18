#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build/ios-arm64"
mkdir -p "$BUILD_DIR"

cd "$SCRIPT_DIR/libgocryptfs"

GO_BIN="$(which go || echo "/opt/local/bin/go")"
SDK_PATH="$(xcrun --sdk iphoneos --show-sdk-path)"
CLANG="$(xcrun --sdk iphoneos --find clang)"

echo "Building iOS arm64 c-archive using $GO_BIN..."
CC="$CLANG" \
CGO_CFLAGS="-isysroot $SDK_PATH -miphoneos-version-min=17.0 -arch arm64" \
CGO_LDFLAGS="-isysroot $SDK_PATH -miphoneos-version-min=17.0 -arch arm64" \
CGO_ENABLED=1 GOOS=ios GOARCH=arm64 "$GO_BIN" build \
  -buildmode=c-archive \
  -trimpath \
  -ldflags="-s -w" \
  -tags without_openssl \
  -o "$BUILD_DIR/libgocryptfs.a" .

echo "Successfully built $BUILD_DIR/libgocryptfs.a"
