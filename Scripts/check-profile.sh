#!/bin/bash
# Asserts that a provisioning profile can ship a Developer ID (Direct) build:
#   - ProvisionsAllDevices is true (a development profile fails on other Macs
#     with `extensionKit error 2`)
#   - it has not expired
#   - it contains the signing certificate
# Exits non-zero with a reason otherwise. make-release.sh and manual builds
# call this before signing.
#
# Usage: check-profile.sh <file.provisionprofile> <signing cert SHA-1>
#        check-profile.sh --plist <decoded profile.plist> <signing cert SHA-1>
set -euo pipefail

fail() { echo "check-profile: $1" >&2; exit 1; }

decoded=""
cleanup() { [ -z "$decoded" ] || rm -f "$decoded"; }
trap cleanup EXIT

if [ "${1:-}" = "--plist" ]; then
  [ $# -eq 3 ] || fail "usage: check-profile.sh --plist <decoded.plist> <cert SHA-1>"
  plist="$2"; identity="$3"; label="$2"
  [ -f "$plist" ] || fail "$plist: no such file"
else
  [ $# -eq 2 ] || fail "usage: check-profile.sh <file.provisionprofile> <cert SHA-1>"
  profile="$1"; identity="$2"; label="$1"
  [ -f "$profile" ] || fail "$profile: no such file"
  decoded="$(mktemp -t gk-profile)"
  security cms -D -i "$profile" -o "$decoded" 2>/dev/null || fail "$profile: not a readable provisioning profile"
  plist="$decoded"
fi

all_devices="$(plutil -extract ProvisionsAllDevices raw -o - "$plist" 2>/dev/null || true)"
[ "$all_devices" = "true" ] || fail "$label: ProvisionsAllDevices is not true (not a Developer ID Direct profile)"

expires="$(plutil -extract ExpirationDate raw -o - "$plist" 2>/dev/null || true)"
[ -n "$expires" ] || fail "$label: no ExpirationDate"
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
[[ "$expires" > "$now" ]] || fail "$label: expired on $expires"

wanted="$(printf '%s' "$identity" | tr '[:lower:]' '[:upper:]')"
index=0
found=0
while cert="$(plutil -extract "DeveloperCertificates.$index" raw -o - "$plist" 2>/dev/null)"; do
  sha="$(printf '%s' "$cert" | base64 -D | shasum -a 1 | awk '{print toupper($1)}')"
  if [ "$sha" = "$wanted" ]; then found=1; break; fi
  index=$((index + 1))
done
[ "$found" = "1" ] || fail "$label: does not contain signing certificate $identity"

echo "check-profile: $(plutil -extract Name raw -o - "$plist" 2>/dev/null || echo "$label") ok (all devices, expires $expires)"
