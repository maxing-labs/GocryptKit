#!/bin/bash
# F-22: the release pipeline must refuse a profile that cannot ship, instead of
# printing a notice and carrying on.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="$REPO/Scripts/check-profile.sh"
IDENTITY="${IDENTITY:-047F5780627C2258AC46D0FA5656007D179BAB86}"
WORK="$(mktemp -d -t gk-profile-test)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
expect() { # <ok|fail> <label> <command...>
  local want="$1" label="$2"; shift 2
  if "$@" >/dev/null 2>&1; then got=ok; else got=fail; fi
  if [ "$got" = "$want" ]; then PASS=$((PASS+1)); echo "  ok   $label"; else FAIL=$((FAIL+1)); echo "  FAIL $label (wanted $want, got $got)"; fi
}

for profile in DirectDistribution.provisionprofile DirectDistribution-host.provisionprofile; do
  expect ok "$profile is accepted" "$CHECK" "$REPO/Scripts/$profile" "$IDENTITY"
  expect fail "$profile is rejected for another certificate" "$CHECK" "$REPO/Scripts/$profile" "0000000000000000000000000000000000000000"
done

decoded="$WORK/profile.plist"
security cms -D -i "$REPO/Scripts/DirectDistribution.provisionprofile" -o "$decoded"
expect ok "decoded profile is accepted" "$CHECK" --plist "$decoded" "$IDENTITY"

cp "$decoded" "$WORK/dev.plist" && plutil -remove ProvisionsAllDevices "$WORK/dev.plist"
expect fail "profile without ProvisionsAllDevices is rejected" "$CHECK" --plist "$WORK/dev.plist" "$IDENTITY"

cp "$decoded" "$WORK/false.plist" && plutil -replace ProvisionsAllDevices -bool false "$WORK/false.plist"
expect fail "ProvisionsAllDevices=false is rejected" "$CHECK" --plist "$WORK/false.plist" "$IDENTITY"

cp "$decoded" "$WORK/expired.plist" && plutil -replace ExpirationDate -date "2020-01-01T00:00:00Z" "$WORK/expired.plist"
expect fail "expired profile is rejected" "$CHECK" --plist "$WORK/expired.plist" "$IDENTITY"

expect fail "missing profile is rejected" "$CHECK" "$WORK/absent.provisionprofile" "$IDENTITY"

echo "check-profile: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
