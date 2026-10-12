<p align="center">
  <img src="Art/AppIcon.png" width="128" height="128" alt="GocryptKit Icon">
</p>

<h1 align="center">GocryptKit</h1>

<p align="center">
  <b>Native, driverless, high-security <a href="https://github.com/rfjakob/gocryptfs">gocryptfs</a> encrypted vault manager for macOS, powered by Apple's modern FSKit framework.</b>
</p>

<p align="center">
  <b>Zero kexts · Zero macFUSE · Zero sudo · Zero security compromises.</b><br>
  SIP (System Integrity Protection) remains fully enabled — no Reduced Security required, no FUSE-T needed.
</p>

<p align="center">
  <a href="https://github.com/maxing-labs/GocryptKit/releases/latest"><img src="https://img.shields.io/github/v/release/maxing-labs/GocryptKit?color=blue&logo=github&label=Release" alt="Latest Release"></a>
  <img src="https://img.shields.io/badge/platform-macOS%2026%2B%20(Apple%20Silicon)-black?logo=apple" alt="Platform">
  <img src="https://img.shields.io/badge/FSKit-Native%20Driverless-purple" alt="FSKit Native">
  <a href="https://github.com/maxing-labs/GocryptKit/releases/latest"><img src="https://img.shields.io/badge/Developer%20ID-Signed%2C%20not%20notarized-yellow?logo=apple" alt="Developer ID signed, not notarized"></a>
  <img src="https://img.shields.io/badge/e2e%20Tests-114%2F114%20Passing-success" alt="Tests">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPL--3.0%20w%2F%20App%20Store%20Exception-orange" alt="License"></a>
</p>

<p align="center">
  <a href="README-zh.md"><b>🇨🇳 中文文档 (README in Chinese)</b></a>
</p>

---

<p align="center">
  <img src="Art/screenshots/mount-demo.gif" width="720" alt="GocryptKit Native Mount & Finder Integration Demo">
</p>

---

## Why GocryptKit?

Mounting encrypted vaults on Apple Silicon Macs has historically forced users into difficult trade-offs:
1. **macFUSE / Kernel Extensions**: Requires rebooting into macOS Recovery and downgrading system security to **"Reduced Security"**, exposing the entire machine to kernel-level vulnerabilities and stability panics.
2. **Proprietary Commercial Wrappers**: Closed-source black boxes cannot be audited for cryptographic backdoors, zero-day vulnerabilities, or silent data leakage.
3. **Container-based Encryption (e.g. VeraCrypt, DMG)**: Modifying a single 10 KB file causes gigabytes of whole-disk images to re-upload on cloud sync drives (Dropbox, iCloud, OneDrive).

**GocryptKit** is built from the ground up for modern macOS:
- **Zero Driver Installs**: Built on Apple's first-party **FSKit** (User-space File System) architecture.
- **Per-File Encryption**: Fully compatible with the battle-tested [gocryptfs](https://github.com/rfjakob/gocryptfs) format. Modifying one file only syncs that single encrypted chunk.
- **100% Open Source & Auditable**: Audited memory wiping (`memset_s`), zero credential persistence in shell history, and strict TLV tagged Keychain transport.

### Feature Comparison Matrix

| Solution | Open Source | Read / Write | Architecture | SIP Intact (No Reduced Security) | Cloud Sync Friendly (Per-File Encryption) | Cross-Platform (Linux / Android) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **GocryptKit** | ✅ Yes (GPLv3) | ✅ Native Full R/W | **Apple Native FSKit** | ✅ Yes (Fully Intact) | ✅ Yes (gocryptfs standard) | ✅ Yes (Linux / DroidFS) |
| **macFUSE + gocryptfs** | ✅ Yes | ✅ Full R/W | Kernel Extension (`kext`) | ❌ No (Requires Recovery downgrade) | ✅ Yes | ✅ Yes |
| **MyCryptFS** | ❌ No (Commercial) | ✅ Full R/W | File Provider API | ✅ Yes | ✅ Yes | ⚠️ Compatible format (Closed Source) |
| **Cryptomator** | ✅ Yes | ✅ Full R/W | FUSE-T / WebDAV | ✅ Yes | ✅ Yes | ❌ Proprietary format (Non-gocryptfs) |
| **VeraCrypt** | ✅ Yes | ✅ Full R/W | Virtual Disk + macFUSE | ❌ No (Requires Recovery downgrade) | ❌ No (Full container re-upload) | ✅ Yes |
| **macOS Encrypted DMG** | ⚠️ System Built-in | ✅ Full R/W | APFS Sparse Image | ✅ Yes | ❌ No (Frequent sync conflicts) | ❌ Mac only |

---

## Highlights & Features

<p align="center">
  <img src="Art/screenshots/finder-volume-flow.png" width="100%" alt="GocryptKit Finder Volume Integration Workflow">
</p>

- **Apple Native Integration**: Built on macOS FSKit. Mounted decrypted volumes appear natively in Finder, Terminal, Spotlight, and standard open/save file dialogs.
- **Hardened Credential Security**: 
  - **Burn-after-reading**: TLV-tagged Keychain protocol (`VCP1`) safely passes credentials and physically scrubs them immediately upon volume mount.
  - **Memory Scrubbing**: Explicit in-memory scrubbing (`memset_s`) for MasterKeys, passwords, and scrypt buffers to eliminate plaintext leaks in swap or crash dumps.
  - **Leak-proof CLI**: Never exposes passwords in process tables (`ps`) or shell history (interactive masked input or `--password-stdin` pipeline).
- **Physical Handle Concurrency Isolation**: Independent file descriptors for read and write paths with granular reader-writer synchronization, eliminating kernel `EBADF` race conditions.
- **Native Extended Attributes (xattr)**: Full macOS xattr support encrypted via EME + DirIV (AES-GCM), preventing `._*` AppleDouble file pollution on cloud storage.
- **Polished MenuBar & App Experience**:
  - Live menu bar status item with dynamic lock state icons (`lock.open.fill` when mounted).
  - Unmount debounce, mutual exclusion locks, and intelligent aggregated conflict dialog when volumes encounter `EBUSY`.
  - Modern SwiftUI client with real-time kernel mount table synchronization (`getfsstat` & `NSWorkspace` mount notifications).

<p align="center">
  <img src="Art/screenshots/menubar-dropdown.png" width="360" alt="GocryptKit MenuBar Quick Access">
</p>

---

## Download & Releases

**v1.4.2** — Accurate Error Codes, rolling up the v1.3.9 – v1.4.1 security and data-integrity fixes (macOS Apple Silicon)

→ [Download GocryptKit-1.4.2.dmg on GitHub Releases](https://github.com/maxing-labs/GocryptKit/releases/tag/v1.4.2)

| Property | Value |
|---|---|
| Package | `GocryptKit-1.4.2.dmg` |
| SHA-256 | `a9d9e51f0e42f87086457fce4b1b1b40f442666690ebed17f4aa1fbe75ff0931` |
| Architecture | Apple Silicon (`arm64-only`) |
| Code Signing | Developer ID Application (Team `QBFSP2CHNW`), **signed but not notarized** |

> **Not notarized since v1.3.9.** The maintainer's Apple Developer Program membership has lapsed, so builds after v1.3.8 are signed with the Developer ID certificate but carry no Apple notarization ticket. Gatekeeper blocks the first launch of such an app: in `/Applications`, **right-click `GocryptKit.app` → Open**, or click **Open Anyway** under **System Settings → Privacy & Security**. Everything else, the file system extension included, works as before. [v1.3.8](https://github.com/maxing-labs/GocryptKit/releases/tag/v1.3.8) is the last notarized build, but it lacks every fix listed in [CHANGELOG.md](CHANGELOG.md) from v1.3.9 on.

Verify the download:

```bash
shasum -a 256 GocryptKit-1.4.2.dmg
# after dragging the app to /Applications: the signature must be valid and belong to team QBFSP2CHNW
codesign --verify --deep --strict --verbose=2 /Applications/GocryptKit.app
codesign -dv /Applications/GocryptKit.app 2>&1 | grep TeamIdentifier
```

---

## Getting Started

### Installation & First Launch

1. Download and drag `GocryptKit.app` to `/Applications`.
2. Launch `GocryptKit.app` once. Gatekeeper blocks the first launch because the build is not notarized (see [Download & Releases](#download--releases)): **right-click the app → Open**, or click **Open Anyway** under **System Settings → Privacy & Security**.
3. Enable the File System Extension:  
   **System Settings → General → Login Items & Extensions → Scroll to bottom → File System Extensions → Toggle GocryptKit ON**.

<p align="center">
  <img src="Art/screenshots/extension-enable.gif" width="560" alt="Enable File System Extension in macOS System Settings">
</p>

<p align="center">
  <img src="Art/screenshots/extension-enable-step1.png" width="48%" alt="System Settings Login Items & Extensions">
  &nbsp;
  <img src="Art/screenshots/extension-enable-step2.png" width="48%" alt="File System Extensions Enablement">
</p>

4. In the app:
   - Click **"Add Existing Vault…"** to mount an existing gocryptfs directory (e.g. from Linux or cloud sync).
   - Click **"Create New Vault…"** to initialize a new encrypted directory.
5. Enter your password and click **"Mount"**. The decrypted filesystem is instantly accessible in Finder!

### Command-Line Interface (CLI)

The application bundle contains a full-featured CLI interface for headless environments or automated scripting:

```bash
# Initialize a new encrypted vault interactively (secure masked input)
/Applications/GocryptKit.app/Contents/MacOS/GocryptKit init <empty-dir>

# Scripted automated vault creation via stdin pipeline
echo "your-password" | /Applications/GocryptKit.app/Contents/MacOS/GocryptKit init <empty-dir> --password-stdin

# Mount an encrypted vault
/Applications/GocryptKit.app/Contents/MacOS/GocryptKit mount <cipher-dir> <mountpoint>

# Unmount a vault (supports -f / --force)
/Applications/GocryptKit.app/Contents/MacOS/GocryptKit umount <mountpoint>
/Applications/GocryptKit.app/Contents/MacOS/GocryptKit umount -f <mountpoint>

# Check FSKit extension status
/Applications/GocryptKit.app/Contents/MacOS/GocryptKit status
```

> ⚠️ **Security Warning**: For privacy and security, the plaintext `--password <string>` argument has been completely removed. Automated scripts should exclusively use the `--password-stdin` stream.

---

## What's New in v1.4.2

v1.4.2 is the first public release since v1.3.8 and ships six versions (v1.3.9 – v1.4.2) of security and data-integrity work:

- **Data integrity**: a file removed or replaced by a rename while still open keeps its handles. Writes no longer bring a deleted file back or land in the file that took over its name (which could leave that file unreadable after a remount). Two racing `O_EXCL` creates can no longer both succeed. File IDs and content locks are shared across handles of the same file.
- **Vault key protection**: on `-plaintextnames` vaults, `gocryptfs.conf` can no longer be deleted, replaced by a rename or edited through the mounted volume.
- **Upstream xattr interoperability**: extended attribute names are encrypted with upstream gocryptfs's fixed IV, so `gocryptfs -fsck` and Linux gocryptfs read them. Attributes written by v1.3.9 or earlier stay readable and are converted the next time they are written.
- **Tampered vault folders**: oversized planted extended attributes, abusive scrypt parameters, planted FIFOs, a `gocryptfs.conf` that is a symlink into a mounted vault and vaults nested inside a mounted vault are refused before they can crash or hang the file system extension.
- **Accurate error codes**: the mounted volume reports the error it actually ran into (`EACCES`, `ENOENT`, `ENOSPC`, `ENOTEMPTY`, …) instead of a generic I/O error, so backup and sync tools react correctly.
- **File attributes**: modification, access and creation times and flags take effect; the append-only flag is refused instead of leaving a file unwritable; read-only new files stay writable to the program that created them; copying a mode 0444 file no longer fails.
- **CLI and keychain hygiene**: unknown options are errors, `--password=…` never echoes the value, an interrupted mount removes its credential, the default mount root `~/Volumes` is private (0700).
- **Text fields**: system text replacement and inline predictions are off in all text fields, so "show password" cannot create a vault with a password you did not type.
- **Quitting**: the app only quits when none of your volumes is mounted and offers to force an unmount only when that lets it quit.

👉 **For the complete per-version log (v0.1.0 to v1.4.2), see [CHANGELOG.md](CHANGELOG.md).**

---

## Building from Source

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

```bash
Scripts/build-dmg.sh
```

Output package will be generated at `build/dist/GocryptKit-1.4.2.dmg`.

---

## Testing

```bash
# Every layer that needs no mount: Go engine (go vet + go test -race), VaultCore (156 tests),
# extension callbacks (45 tests; --tsan repeats them under Thread Sanitizer) and the host scripts.
# Logs go to build/test-logs/<layer>.log.
Scripts/test.sh fast [--tsan]

# End-to-end suite on a real mount (114 checks). Needs the app installed in /Applications with
# its extension enabled, and refuses to start while any gocryptfs volume is mounted.
Tests/e2e/make-samples.sh
Scripts/test.sh mount
```

---

## License & Attribution

This project is licensed under the [GNU General Public License v3.0 (GPL-3.0)](LICENSE) with the **Apple App Store Exception (Version 1.0)**.

The underlying engine `Engine/libgocryptfs` is derived from upstream [gocryptfs](https://github.com/rfjakob/gocryptfs) and is licensed under the MIT License.

The folder-key icon glyph is designed by [Flaticon](https://www.flaticon.com/free-icon/folder_10303679) (Icon ID: `10303679`) and used under the Flaticon Free License. See [`Art/ATTRIBUTION.md`](Art/ATTRIBUTION.md) for details.
