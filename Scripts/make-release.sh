#!/bin/bash
# GocryptKit release pipeline: Release archive → embed Developer ID (Direct) profile →
# inside-out codesigning → optional App notarization → build DMG → optional DMG notarization → stapling.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

IDENTITY="${IDENTITY:-047F5780627C2258AC46D0FA5656007D179BAB86}"   # Developer ID Application, exp 2031-08-24
NOTARY_PROFILE="${NOTARY_PROFILE:-fcitx5-notary}"
PROFILE_EXT="$REPO/Scripts/DirectDistribution.provisionprofile"
PROFILE_APP="$REPO/Scripts/DirectDistribution-host.provisionprofile"
ENTS_EXT="$REPO/Scripts/ext-entitlements.plist"
ENTS_APP="$REPO/Scripts/app-entitlements.plist"
VERSION="$(awk -F'"' '/MARKETING_VERSION/{print $2; exit}' project.yml)"

ARCHIVE="build/archive/GocryptKit.xcarchive"
STAGE="build/stage"
DIST="build/dist"
APP="$STAGE/GocryptKit.app"
EXT="$APP/Contents/Extensions/GocryptKitExt.appex"
DMG="$DIST/GocryptKit-$VERSION.dmg"

say() { printf '\n\033[1m── %s\033[0m\n' "$1"; }

say "1/8  Rebuild Go engine and xcframework"
Engine/build-darwin.sh >/dev/null
Engine/make-xcframework.sh >/dev/null
echo "     libgocryptfs.xcframework ready"

say "2/8  Release archive"
xcodegen generate >/dev/null
rm -rf "$ARCHIVE"
xcodebuild -project GocryptKit.xcodeproj -scheme GocryptKit \
  -configuration Release -destination 'generic/platform=macOS' \
  -archivePath "$ARCHIVE" archive -allowProvisioningUpdates >/dev/null
echo "     $ARCHIVE"

say "3/8  Stage and embed Developer ID (Direct) profile"
if [ -f "$PROFILE_EXT" ] && [ -f "$PROFILE_APP" ]; then
  rm -rf "$STAGE"; mkdir -p "$STAGE"
  cp -R "$ARCHIVE/Products/Applications/GocryptKit.app" "$APP"
  cp "$PROFILE_EXT" "$EXT/Contents/embedded.provisionprofile"
  cp "$PROFILE_APP" "$APP/Contents/embedded.provisionprofile"
  echo "     ext : $(security cms -D -i "$PROFILE_EXT" | plutil -extract Name raw -)"
  echo "     host: $(security cms -D -i "$PROFILE_APP" | plutil -extract Name raw -)"
else
  echo "     DirectDistribution profiles not found, continuing with archive signature..."
  rm -rf "$STAGE"; mkdir -p "$STAGE"
  cp -R "$ARCHIVE/Products/Applications/GocryptKit.app" "$APP"
fi

say "4/8  Inside-out signing (strictly no --deep)"
if security find-identity -v -p codesigning | grep -q "$IDENTITY"; then
  codesign --force --options runtime --timestamp \
    --sign "$IDENTITY" --entitlements "$ENTS_EXT" "$EXT"
  codesign --force --options runtime --timestamp \
    --sign "$IDENTITY" --entitlements "$ENTS_APP" "$APP"
  echo "     ✓ Resigned with Developer ID certificate"
fi

if ! "$APP/Contents/MacOS/GocryptKit" version >/dev/null 2>&1; then
  echo "Fatal: Signed host failed to launch (blocked by AMFI)."
  exit 1
fi
echo "     ✓ Signed host launches successfully"
codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | tail -2

say "5/8  Validate profile type"
if [ -f "$APP/Contents/embedded.provisionprofile" ]; then
  for pp in "$APP/Contents/embedded.provisionprofile" "$EXT/Contents/embedded.provisionprofile"; do
    security cms -D -i "$pp" > /tmp/_pp0.plist
    /usr/libexec/PlistBuddy -c 'Print :ProvisionsAllDevices' /tmp/_pp0.plist >/dev/null 2>&1 \
      || echo "Notice: $pp lacks ProvisionsAllDevices (normal in dev environment)"
  done
  rm -f /tmp/_pp0.plist
fi

say "6/8  Notarize App and staple (optional)"
submit_and_wait() {
  local target="$1"
  local attempts=3
  for i in $(seq 1 $attempts); do
    echo "     Submitting for notarization (attempt $i/$attempts): $target"
    if xcrun notarytool submit "$target" --keychain-profile "$NOTARY_PROFILE" --wait --timeout 20m; then
      return 0
    fi
    echo "     ⚠️  Notarization submission failed or timed out, retrying in 5s..."
    sleep 5
  done
  echo "     ❌ Notarization failed after $attempts attempts"
  return 1
}

CAN_NOTARIZE=0
if [ "${SKIP_NOTARIZATION:-0}" != "1" ] && xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
  CAN_NOTARIZE=1
fi

if [ "$CAN_NOTARIZE" = "1" ]; then
  rm -f build/GocryptKit-notarize.zip
  ditto -c -k --keepParent "$APP" build/GocryptKit-notarize.zip
  submit_and_wait build/GocryptKit-notarize.zip
  xcrun stapler staple "$APP"
else
  echo "     Skipping App notarization (notary profile not configured or SKIP_NOTARIZATION=1)"
fi

say "7/8  Build and sign DMG"
mkdir -p "$DIST"
# Use --skip-jenkins in non-interactive or automated environments to prevent Finder AppleScript hang
if [ -n "${CI:-}" ] || [ -z "${TERM:-}" ] || ! tty -s 2>/dev/null; then
  create-dmg --volname "GocryptKit" --app-drop-link 450 190 --no-internet-enable \
    --skip-jenkins "$DMG" "$STAGE" >/dev/null
else
  if ! create-dmg --volname "GocryptKit" --window-pos 200 120 --window-size 600 400 \
    --icon-size 100 --icon "GocryptKit.app" 150 190 --hide-extension "GocryptKit.app" \
    --app-drop-link 450 190 --no-internet-enable "$DMG" "$STAGE" >/dev/null 2>&1; then
    echo "     Finder AppleScript timed out, falling back to --skip-jenkins mode..."
    rm -f "$DMG"
    create-dmg --volname "GocryptKit" --app-drop-link 450 190 --no-internet-enable \
      --skip-jenkins "$DMG" "$STAGE" >/dev/null
  fi
fi

if security find-identity -v -p codesigning | grep -q "$IDENTITY"; then
  codesign --force --sign "$IDENTITY" --timestamp "$DMG"
fi

say "8/8  Notarize DMG and staple (optional)"
if [ "$CAN_NOTARIZE" = "1" ]; then
  submit_and_wait "$DMG"
  xcrun stapler staple "$DMG"
  xcrun stapler validate "$DMG"
  spctl -a -t open --context context:primary-signature -vv "$DMG"
else
  echo "     Skipping DMG notarization and stapling"
fi

say "Done"
echo "Artifact : $DMG"
echo "Size     : $(du -h "$DMG" | cut -f1)"
echo "SHA256   : $(shasum -a 256 "$DMG" | awk '{print $1}')"
