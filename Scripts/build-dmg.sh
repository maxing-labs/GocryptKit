#!/bin/bash
# GocryptKit DMG 构建脚本：一键完成 xcframework 生成、Release 编译、App 打包与 DMG 制作
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

say "1/5  检查/编译 Go 引擎 xcframework"
if [ ! -d "Engine/build/libgocryptfs.xcframework" ]; then
  Engine/build-darwin.sh >/dev/null
  Engine/make-xcframework.sh >/dev/null
fi
echo "     libgocryptfs.xcframework 就绪"

say "2/5  生成 Xcode 工程并执行 Release 编译"
xcodegen generate >/dev/null
xcodebuild -project GocryptKit.xcodeproj -scheme GocryptKit \
  -configuration Release build >/dev/null

BUILT_APP="$(find ~/Library/Developer/Xcode/DerivedData/GocryptKit-*/Build/Products/Release/GocryptKit.app -maxdepth 0 2>/dev/null | head -n 1)"
if [ -z "$BUILT_APP" ] || [ ! -d "$BUILT_APP" ]; then
  # 兜底查找本地 build 产物
  BUILT_APP="$(find build -name "GocryptKit.app" -type d 2>/dev/null | head -n 1)"
fi

if [ -z "$BUILT_APP" ] || [ ! -d "$BUILT_APP" ]; then
  echo "错误：未找到编译出的 GocryptKit.app"
  exit 1
fi
echo "     已找到构建产物: $BUILT_APP"

say "3/5  暂存 App 并校验版本"
rm -rf "$STAGE"; mkdir -p "$STAGE"
cp -R "$BUILT_APP" "$APP"
"$APP/Contents/MacOS/GocryptKit" version

say "4/5  制作 DMG"
mkdir -p "$DIST"
rm -f "$DMG"

# 在非交互终端或自动化环境中直接使用 --skip-jenkins，避免 Finder AppleScript 挂起
if [ -n "${CI:-}" ] || [ -z "${TERM:-}" ] || ! tty -s 2>/dev/null; then
  create-dmg --volname "GocryptKit" --app-drop-link 450 190 --no-internet-enable \
    --skip-jenkins "$DMG" "$STAGE" >/dev/null
else
  if ! create-dmg --volname "GocryptKit" --window-pos 200 120 --window-size 600 400 \
    --icon-size 100 --icon "GocryptKit.app" 150 190 --hide-extension "GocryptKit.app" \
    --app-drop-link 450 190 --no-internet-enable "$DMG" "$STAGE" >/dev/null 2>&1; then
    echo "     Finder AppleScript 响应超时，降级至 --skip-jenkins 模式制作 DMG..."
    rm -f "$DMG"
    create-dmg --volname "GocryptKit" --app-drop-link 450 190 --no-internet-enable \
      --skip-jenkins "$DMG" "$STAGE" >/dev/null
  fi
fi

say "5/5  签名 DMG"
if security find-identity -v -p codesigning | grep -q "$IDENTITY"; then
  codesign --force --sign "$IDENTITY" --timestamp "$DMG"
  echo "     ✓ 已使用 Developer ID 证书签名 DMG: $IDENTITY"
else
  codesign --force --sign - "$DMG"
  echo "     ✓ 已使用 Ad-hoc 签名 DMG"
fi

say "完成"
rm -rf "$STAGE"
echo "产物   : $DMG"
echo "大小   : $(du -h "$DMG" | cut -f1)"
echo "SHA256 : $(shasum -a 256 "$DMG" | awk '{print $1}')"
