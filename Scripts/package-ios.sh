#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== 打包 GocryptfsKit iOS/iPadOS 应用 ==="

cd "$ROOT_DIR"

OUTPUT_DIR="$ROOT_DIR/build/ios-products"
mkdir -p "$OUTPUT_DIR"

TEMP_BUILD="/tmp/gocryptfs_ios_pack"
rm -rf "$TEMP_BUILD"
mkdir -p "$TEMP_BUILD"

# 1. 编译 VaultCore (iOS arm64 静态库)
echo ">> 编译 VaultCore iOS 模块..."
xcrun --sdk iphoneos swiftc \
  -target arm64-apple-ios17.0 \
  -module-name VaultCore \
  -emit-module -emit-module-path "$TEMP_BUILD/VaultCore.swiftmodule" \
  -emit-library -static \
  Packages/VaultCore/Sources/VaultCore/*.swift \
  -I Engine/build/libgocryptfs.xcframework/ios-arm64/Headers \
  -L Engine/build/libgocryptfs.xcframework/ios-arm64 \
  -o "$TEMP_BUILD/libVaultCore.a"

# 2. 编译可执行二进制
echo ">> 编译并链接 GocryptfsKit iOS 可执行文件..."
xcrun --sdk iphoneos swiftc \
  -target arm64-apple-ios17.0 \
  -module-name GocryptfsKit \
  -emit-executable \
  App-iOS/*.swift \
  -I "$TEMP_BUILD" \
  -L "$TEMP_BUILD" \
  -lVaultCore \
  -I Engine/build/libgocryptfs.xcframework/ios-arm64/Headers \
  Engine/build/libgocryptfs.xcframework/ios-arm64/libgocryptfs.a \
  -lresolv \
  -o "$TEMP_BUILD/GocryptfsKit"

# 3. 组装 .app Bundle
APP_DIR="$OUTPUT_DIR/GocryptfsKit.app"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR"

cp "$TEMP_BUILD/GocryptfsKit" "$APP_DIR/GocryptfsKit"
chmod +x "$APP_DIR/GocryptfsKit"

# 生成 Info.plist
cat << 'PLIST' > "$APP_DIR/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleDisplayName</key>
	<string>GocryptfsKit</string>
	<key>CFBundleExecutable</key>
	<string>GocryptfsKit</string>
	<key>CFBundleIdentifier</key>
	<string>com.xwei.GocryptfsKit.iOS</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>GocryptfsKit</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>0.1.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>LSRequiresIPhoneOS</key>
	<true/>
	<key>MinimumOSVersion</key>
	<string>17.0</string>
	<key>ITSAppUsesNonExemptEncryption</key>
	<false/>
	<key>UIDeviceFamily</key>
	<array>
		<integer>1</integer>
		<integer>2</integer>
	</array>
	<key>UILaunchScreen</key>
	<dict/>
	<key>UISupportedInterfaceOrientations</key>
	<array>
		<string>UIInterfaceOrientationPortrait</string>
		<string>UIInterfaceOrientationLandscapeLeft</string>
		<string>UIInterfaceOrientationLandscapeRight</string>
	</array>
	<key>UISupportedInterfaceOrientations~ipad</key>
	<array>
		<string>UIInterfaceOrientationPortrait</string>
		<string>UIInterfaceOrientationPortraitUpsideDown</string>
		<string>UIInterfaceOrientationLandscapeLeft</string>
		<string>UIInterfaceOrientationLandscapeRight</string>
	</array>
	<key>NSPhotoLibraryUsageDescription</key>
	<string>Access to your photo library is needed to encrypt and store photos into your vault.</string>
</dict>
</plist>
PLIST

# 拷贝隐私清单
if [ -f "App-iOS/PrivacyInfo.xcprivacy" ]; then
    cp "App-iOS/PrivacyInfo.xcprivacy" "$APP_DIR/"
fi

# 拷贝图标资源
if [ -d "/tmp/ios_build/assets" ]; then
    cp -R /tmp/ios_build/assets/*.png "$APP_DIR/" 2>/dev/null || true
fi
cp App-iOS/Assets.xcassets/AppIcon.appiconset/icon_512x512@2x.png "$APP_DIR/AppIcon60x60@2x.png" 2>/dev/null || true

# 4. 代码签名 (优先使用 Apple Development 证书，若无则使用 Ad-Hoc 签名)
SIGN_IDENTITY="$(security find-identity -p codesigning -v | awk -F'"' '/Apple Development/{print $2; exit}')"
if [ -n "$SIGN_IDENTITY" ]; then
    echo ">> 使用开发者证书签名: $SIGN_IDENTITY"
    codesign --force --sign "$SIGN_IDENTITY" --timestamp=none "$APP_DIR" || codesign --force --sign - "$APP_DIR"
else
    echo ">> 未检测到 Apple Development 证书，使用 Ad-Hoc 签名..."
    codesign --force --sign - "$APP_DIR"
fi

# 5. 打包成 .ipa
echo ">> 打包为 IPA 安装文件..."
PAYLOAD_DIR="$TEMP_BUILD/Payload"
mkdir -p "$PAYLOAD_DIR"
cp -R "$APP_DIR" "$PAYLOAD_DIR/"

IPA_PATH="$OUTPUT_DIR/GocryptfsKit.ipa"
rm -f "$IPA_PATH"
(cd "$TEMP_BUILD" && zip -q -r "$IPA_PATH" Payload)

echo ""
echo "🎉 打包完成！"
echo "  - APP 文件: $APP_DIR"
echo "  - IPA 文件: $IPA_PATH"
