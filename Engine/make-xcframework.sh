#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "build/macos-arm64/libgocryptfs.a" ]; then
    ./build-darwin.sh
fi

if [ ! -f "build/ios-arm64/libgocryptfs.a" ]; then
    ./build-ios.sh
fi

mkdir -p build/include
cp build/libgocryptfs.h build/include/

cat << 'MOD' > build/include/module.modulemap
module libgocryptfs [system] {
    header "libgocryptfs.h"
    export *
}
MOD

rm -rf build/libgocryptfs.xcframework
xcodebuild -create-xcframework \
    -library build/macos-arm64/libgocryptfs.a \
    -headers build/include \
    -library build/ios-arm64/libgocryptfs.a \
    -headers build/include \
    -output build/libgocryptfs.xcframework

echo "Successfully built libgocryptfs.xcframework with macOS & iOS arm64 slices"
