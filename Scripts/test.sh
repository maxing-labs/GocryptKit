#!/bin/bash
# Runs the test layers from anywhere in the repository.
#
#   Scripts/test.sh fast [--tsan]
#       Go engine, VaultCore, extension callbacks and the host script tests.
#       Mounts nothing and builds no app, so nothing gets registered with
#       LaunchServices. --tsan runs the extension tests a second time under
#       Thread Sanitizer. Each layer logs to build/test-logs/<layer>.log; all
#       layers run, and the exit status is 1 if any failed.
#
#   Scripts/test.sh mount [args...]
#       End-to-end on the app installed in /Applications (Tests/e2e/run-e2e.sh;
#       arguments and variables such as SECURITY_ONLY=1 pass through). Refuses
#       to start while any gocryptfs volume is mounted: a hung case ends
#       extension processes, and a stuck FSKit stalls every FSKit volume.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

# The tests link Engine/build/libgocryptfs.xcframework, which make-xcframework.sh
# only rebuilds from slices that are missing. A Go change that did not go
# through build-darwin.sh and make-xcframework.sh would be tested against the
# old engine.
check_engine() {
  local mac=Engine/build/macos-arm64/libgocryptfs.a
  local framework=Engine/build/libgocryptfs.xcframework/macos-arm64/libgocryptfs.a
  local ios=Engine/build/ios-arm64/libgocryptfs.a
  local rebuild="cd Engine && ./build-darwin.sh && ./build-ios.sh && ./make-xcframework.sh"
  if [ ! -f "$mac" ] || [ ! -f "$framework" ]; then
    echo "error: the engine is not built; run: $rebuild" >&2
    exit 1
  fi
  if [ -n "$(find Engine/libgocryptfs -name '*.go' ! -name '*_test.go' -newer "$mac" -print -quit)" ]; then
    echo "error: Go sources are newer than $mac; run: $rebuild" >&2
    exit 1
  fi
  if ! cmp -s "$mac" "$framework"; then
    echo "error: the xcframework holds an older macOS slice; run: $rebuild" >&2
    exit 1
  fi
  if [ ! -f "$ios" ] || [ -n "$(find Engine/libgocryptfs -name '*.go' ! -name '*_test.go' -newer "$ios" -print -quit)" ]; then
    echo "warning: the iOS slice is older than the Go sources (the tests do not use it)" >&2
  fi
}

failed=()
LOGS="$REPO/build/test-logs"

# run <layer> <command...>: runs the command with its output in the layer's log.
run() {
  local layer="$1"
  shift
  printf '%-10s ' "$layer"
  if "$@" >"$LOGS/$layer.log" 2>&1; then
    echo "ok"
  else
    echo "FAILED (build/test-logs/$layer.log)"
    failed+=("$layer")
  fi
}

ext_tests() {
  xcodegen generate &&
    xcodebuild -project GocryptKit.xcodeproj -scheme GocryptKitExtTests -configuration Debug \
      -destination platform=macOS,arch=arm64 -derivedDataPath build/ExtDD \
      CODE_SIGNING_ALLOWED=NO ENABLE_DEBUG_DYLIB=NO "$@" test
}

host_tests() {
  local status=0 t
  for t in Tests/host/*-test.sh; do
    "$t" || { echo "FAILED: $t"; status=1; }
  done
  return $status
}

fast() {
  local tsan=0
  case "${1:-}" in
    "") ;;
    --tsan) tsan=1 ;;
    *) usage ;;
  esac
  check_engine
  mkdir -p "$LOGS"
  run go bash -c 'cd Engine/libgocryptfs && go vet -tags without_openssl . && go test -tags without_openssl -race -count=1 ./...'
  run vaultcore swift test --package-path Packages/VaultCore
  run ext ext_tests
  if [ "$tsan" = 1 ]; then
    run ext-tsan ext_tests -enableThreadSanitizer YES TEST_RUNNER_TSAN_OPTIONS=halt_on_error=1
  fi
  run host host_tests
  if [ ${#failed[@]} -gt 0 ]; then
    echo "failed: ${failed[*]}"
    exit 1
  fi
}

mount_layer() {
  local mounted
  mounted="$(/sbin/mount | grep -i gocryptfs || true)"
  if [ -n "$mounted" ]; then
    echo "refusing to run: a gocryptfs volume is mounted; unmount it first:" >&2
    echo "$mounted" >&2
    exit 1
  fi
  local plist=/Applications/GocryptKit.app/Contents/Info.plist
  if [ -f "$plist" ]; then
    echo "installed: GocryptKit $(defaults read "$plist" CFBundleShortVersionString) ($(defaults read "$plist" CFBundleVersion))"
  fi
  exec ./Tests/e2e/run-e2e.sh "$@"
}

case "${1:-}" in
  fast) shift; fast "$@" ;;
  mount) shift; mount_layer "$@" ;;
  *) usage ;;
esac
