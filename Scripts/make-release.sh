#!/bin/bash
# GocryptKit 发布流水线：Release 归档 → 嵌入 Developer ID(Direct) profile →
# 由内向外签名 → 可选公证 App → 打 DMG → 可选公证 DMG → 装订。
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

say "1/8  重建 Go 引擎与 xcframework"
Engine/build-darwin.sh >/dev/null
Engine/make-xcframework.sh >/dev/null
echo "     libgocryptfs.xcframework 就绪"

say "2/8  Release 归档"
xcodegen generate >/dev/null
rm -rf "$ARCHIVE"
xcodebuild -project GocryptKit.xcodeproj -scheme GocryptKit \
  -configuration Release -destination 'generic/platform=macOS' \
  -archivePath "$ARCHIVE" archive -allowProvisioningUpdates >/dev/null
echo "     $ARCHIVE"

say "3/8  暂存并嵌入 Developer ID (Direct) profile"
if [ -f "$PROFILE_EXT" ] && [ -f "$PROFILE_APP" ]; then
  rm -rf "$STAGE"; mkdir -p "$STAGE"
  cp -R "$ARCHIVE/Products/Applications/GocryptKit.app" "$APP"
  cp "$PROFILE_EXT" "$EXT/Contents/embedded.provisionprofile"
  cp "$PROFILE_APP" "$APP/Contents/embedded.provisionprofile"
  echo "     ext : $(security cms -D -i "$PROFILE_EXT" | plutil -extract Name raw -)"
  echo "     host: $(security cms -D -i "$PROFILE_APP" | plutil -extract Name raw -)"
else
  echo "     未找到 DirectDistribution profile，以当前归档签名继续暂存..."
  rm -rf "$STAGE"; mkdir -p "$STAGE"
  cp -R "$ARCHIVE/Products/Applications/GocryptKit.app" "$APP"
fi

say "4/8  由内向外签名（严禁 --deep）"
if security find-identity -v -p codesigning | grep -q "$IDENTITY"; then
  codesign --force --options runtime --timestamp \
    --sign "$IDENTITY" --entitlements "$ENTS_EXT" "$EXT"
  codesign --force --options runtime --timestamp \
    --sign "$IDENTITY" --entitlements "$ENTS_APP" "$APP"
  echo "     ✓ 已使用 Developer ID 证书重新签名"
fi

if ! "$APP/Contents/MacOS/GocryptKit" version >/dev/null 2>&1; then
  echo "致命：签名后的宿主无法运行（AMFI 拦截）。"
  exit 1
fi
echo "     ✓ 签名后宿主可正常启动"
codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | tail -2

say "5/8  校验 profile 类型"
if [ -f "$APP/Contents/embedded.provisionprofile" ]; then
  for pp in "$APP/Contents/embedded.provisionprofile" "$EXT/Contents/embedded.provisionprofile"; do
    security cms -D -i "$pp" > /tmp/_pp0.plist
    /usr/libexec/PlistBuddy -c 'Print :ProvisionsAllDevices' /tmp/_pp0.plist >/dev/null 2>&1 \
      || echo "提示：$pp 缺少 ProvisionsAllDevices（开发环境正常）"
  done
  rm -f /tmp/_pp0.plist
fi

say "6/8  公证 App 并装订（可选）"
CAN_NOTARIZE=0
if [ "${SKIP_NOTARIZATION:-0}" != "1" ] && xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
  CAN_NOTARIZE=1
fi

if [ "$CAN_NOTARIZE" = "1" ]; then
  rm -f build/GocryptKit-notarize.zip
  ditto -c -k --keepParent "$APP" build/GocryptKit-notarize.zip
  xcrun notarytool submit build/GocryptKit-notarize.zip --keychain-profile "$NOTARY_PROFILE" --wait | tail -3
  xcrun stapler staple "$APP"
else
  echo "     跳过 App 公证（未配置 notary profile 或 SKIP_NOTARIZATION=1）"
fi

say "7/8  制作并签名 DMG"
mkdir -p "$DIST"
rm -f "$DMG"
if ! create-dmg --volname "GocryptKit" --window-pos 200 120 --window-size 600 400 \
  --icon-size 100 --icon "GocryptKit.app" 150 190 --hide-extension "GocryptKit.app" \
  --app-drop-link 450 190 --no-internet-enable "$DMG" "$STAGE" >/dev/null 2>&1; then
  echo "     Finder AppleScript 响应超时，降级至 --skip-jenkins 模式制作 DMG..."
  rm -f "$DMG"
  create-dmg --volname "GocryptKit" --app-drop-link 450 190 --no-internet-enable \
    --skip-jenkins "$DMG" "$STAGE" >/dev/null
fi

if security find-identity -v -p codesigning | grep -q "$IDENTITY"; then
  codesign --force --sign "$IDENTITY" --timestamp "$DMG"
fi

say "8/8  公证 DMG 并装订（可选）"
if [ "$CAN_NOTARIZE" = "1" ]; then
  xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait | tail -3
  xcrun stapler staple "$DMG"
  xcrun stapler validate "$DMG"
  spctl -a -t open --context context:primary-signature -vv "$DMG"
else
  echo "     跳过 DMG 公证与装订"
fi

say "完成"
echo "产物   : $DMG"
echo "大小   : $(du -h "$DMG" | cut -f1)"
echo "SHA256 : $(shasum -a 256 "$DMG" | awk '{print $1}')"
