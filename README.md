# GocryptKit

Native, driverless, high-security [gocryptfs](https://github.com/rfjakob/gocryptfs) encrypted vault manager for macOS, powered by Apple's modern **FSKit** framework.

**Zero kexts. Zero macFUSE. Zero sudo. Zero security compromises.**  
SIP (System Integrity Protection) remains fully enabled — no Reduced Security required, no FUSE-T needed.

[中文文档 (README in Chinese)](README-zh.md)

---

## Highlights & Features

- **Apple Native Integration**: Built on macOS FSKit (User-space File System framework). Mounts appear directly in Finder, Terminal, and standard file dialogs.
- **Hardened Credential Security**: 
  - TLV-tagged Keychain protocol (consume-on-mount / burn-after-reading).
  - Explicit in-memory scrubbing (`memset_s`) for MasterKeys, passwords, and scrypt buffers to prevent secrets from landing on swap or core dumps.
  - CLI never exposes passwords in process tables (`ps`) or shell history (interactive no-echo input or `--password-stdin` pipeline).
- **Physical Handle Concurrency Isolation**: Read and write file descriptors are physically decoupled with granular reader-writer locks, eliminating kernel `EBADF` race conditions.
- **Native Extended Attributes (xattr)**: Full macOS xattr support encrypted via EME + DirIV (AES-GCM), preventing `._*` AppleDouble file pollution.
- **MenuBar & App Experience**:
  - Live status item with dynamic lock state icons (`lock.open.fill` when mounted).
  - Unmount debounce & mutual exclusion locks.
  - Aggregated conflict dialog when multiple volumes encounter `EBUSY`.
- **Modern SwiftUI Client**: Effortlessly create new encrypted vaults or mount existing directories. Real-time kernel mount table synchronization (`getfsstat`).

---

## Download & Releases

**v1.2.4** — Initial Open Source Release (macOS Apple Silicon)

→ [Download on GitHub Releases](https://github.com/maxing-labs/GocryptKit/releases/tag/v1.2.4)

| Property | Value |
|---|---|
| Package | `GocryptKit-1.2.4.dmg` |
| Architecture | Apple Silicon (`arm64-only`) |
| Code Signing | Developer ID Application (Apple Notarized & Stapled) |

Verify the release DMG:

```bash
shasum -a 256 GocryptKit-1.2.4.dmg
spctl -a -t open --context context:primary-signature -vv GocryptKit-1.2.4.dmg
```

See [Getting Started](#getting-started) below for setup instructions.

---

## Getting Started

### Installation & First Launch

1. Drag `GocryptKit.app` to `/Applications`.
2. Launch `GocryptKit.app` once.
3. Enable the File System Extension:  
   **System Settings → General → Login Items & Extensions → Scroll to bottom → File System Extensions → Toggle GocryptKit ON**.
4. In the app, click **"Add Existing Vault…"** to select a cipher directory, or **"Create New Vault…"** to initialize an empty directory.
5. Enter your password and click **"Mount"**. The decrypted filesystem is instantly accessible in Finder!

### Command-Line Interface (CLI)

The application bundle contains a full-featured CLI interface:

```bash
# Initialize a new encrypted vault interactively (secure masked input)
/Applications/GocryptKit.app/Contents/MacOS/GocryptKit init <empty-dir>

# Scripted automated vault creation via stdin pipeline
echo "your-password" | /Applications/GocryptKit.app/Contents/MacOS/GocryptKit init <empty-dir> --password-stdin

# Mount an encrypted vault
/Applications/GocryptKit.app/Contents/MacOS/GocryptKit mount <cipher-dir> <mountpoint>

# Unmount a vault
/Applications/GocryptKit.app/Contents/MacOS/GocryptKit umount <mountpoint>

# Check FSKit extension status
/Applications/GocryptKit.app/Contents/MacOS/GocryptKit status
```

> ⚠️ **Security Warning**: For privacy and security, the plaintext `--password <string>` argument has been completely removed. Automated scripts should exclusively use the `--password-stdin` stream.

---

## Prerequisites & Building from Source

### System Requirements

- **Operating System**: macOS 26.0+ (Apple Silicon)
- **Build Tools**: Xcode 26+, Go 1.25+, [XcodeGen](https://github.com/yonaskolb/XcodeGen), `create-dmg`
- **Testing Tools**: `ffmpeg` (with libmp3lame / libx264)

### Build Steps

```bash
git clone https://github.com/maxing-labs/GocryptKit.git
cd GocryptKit

# 1. Build the Go core engine (darwin arm64 c-archive)
Engine/build-darwin.sh

# 2. Package into an XCFramework
Engine/make-xcframework.sh

# 3. Generate Xcode project from project.yml
xcodegen generate

# 4. Build Release application
xcodebuild -project GocryptKit.xcodeproj -scheme GocryptKit \
  -configuration Release build
```

> **Note for External Contributors**:  
> `project.yml` includes maintainer signing defaults. When building locally with your personal Apple ID, change `DEVELOPMENT_TEAM` in `project.yml` or select your personal team under Xcode project signing settings.

### Building DMG Package

To produce an installation DMG:

```bash
Scripts/build-dmg.sh
```

Output: `build/dist/GocryptKit-1.2.4.dmg`.

---

## Testing

```bash
# Run VaultCore unit test suite (95 assertions covering crypto, TLV payloads, xattrs)
swift test --package-path Packages/VaultCore

# Run end-to-end integration test suite (87 tests, requires enabled AppEx)
Tests/e2e/make-samples.sh
Tests/e2e/run-e2e.sh
```

---

## License

This project is licensed under the [GNU General Public License v3.0 (GPL-3.0)](LICENSE) with the **Apple App Store Exception (Version 1.0)**.

The underlying engine `Engine/libgocryptfs` is derived from upstream [gocryptfs](https://github.com/rfjakob/gocryptfs) and is licensed under the MIT License.

### Attribution

The folder-key icon glyph is designed by [Flaticon](https://www.flaticon.com/free-icon/folder_10303679) (Icon ID: `10303679`) and used under the Flaticon Free License. See [`Art/ATTRIBUTION.md`](Art/ATTRIBUTION.md) for details.
