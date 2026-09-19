#!/bin/bash
# GocryptKit DMG build script: one-stop xcframework build, Release compilation, App staging, and DMG packaging
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

IDENTITY="${IDENTITY:-047F5780627C2258AC46D0FA5656007D179BAB86}"   # Developer ID Application
VERSION="$(awk -F'"' '/MARKETING_VERSION/{print $2; exit}' project.yml)"
STAGE="build/stage"
DIST="build/dist"
APP="$STAGE/GocryptKit.app"
DMG="$DIST/GocryptKit-$VERSION.dmg"

say() { printf '\n\033[1m── %s\033[0m\n' "$1"; }

say "1/5  Check/build Go engine xcframework"
if [ ! -d "Engine/build/libgocryptfs.xcframework" ]; then
  Engine/build-darwin.sh >/dev/null
  Engine/make-xcframework.sh >/dev/null
fi
echo "     libgocryptfs.xcframework ready"

say "2/5  Generate Xcode project and build Release"
xcodegen generate >/dev/null
xcodebuild -project GocryptKit.xcodeproj -scheme GocryptKit \
  -configuration Release build >/dev/null

BUILT_APP="$(find ~/Library/Developer/Xcode/DerivedData/GocryptKit-*/Build/Products/Release/GocryptKit.app -maxdepth 0 2>/dev/null | head -n 1)"
if [ -z "$BUILT_APP" ] || [ ! -d "$BUILT_APP" ]; then
  # Fallback to local build products
  BUILT_APP="$(find build -name "GocryptKit.app" -type d 2>/dev/null | head -n 1)"
fi

if [ -z "$BUILT_APP" ] || [ ! -d "$BUILT_APP" ]; then
  echo "Error: Could not find built GocryptKit.app"
  exit 1
fi
echo "     Found build product: $BUILT_APP"

say "3/5  Stage App and verify version"
rm -rf "$STAGE"; mkdir -p "$STAGE"
cp -R "$BUILT_APP" "$APP"
"$APP/Contents/MacOS/GocryptKit" version

say "4/5  Build DMG"
mkdir -p "$DIST"
rm -f "$DMG"

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

say "5/5  Sign DMG"
if security find-identity -v -p codesigning | grep -q "$IDENTITY"; then
  codesign --force --sign "$IDENTITY" --timestamp "$DMG"
  echo "     ✓ Signed DMG with Developer ID: $IDENTITY"
else
  codesign --force --sign - "$DMG"
  echo "     ✓ Signed DMG with Ad-hoc signature"
fi

say "Done"
rm -rf "$STAGE"
echo "Artifact : $DMG"
echo "Size     : $(du -h "$DMG" | cut -f1)"
echo "SHA256   : $(shasum -a 256 "$DMG" | awk '{print $1}')"
