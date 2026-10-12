# Changelog

All notable changes to [GocryptKit](https://github.com/maxing-labs/GocryptKit) are documented in this file.

[🇨🇳 中文更新日志 (Changelog in Chinese)](CHANGELOG-zh.md) · [Back to README](README.md)

---

## v1.4.2 (2026-10-10) — Accurate Error Codes
- **Error codes**: the mounted volume now reports the error it actually ran into, as other file systems do. A folder you may not read was reported as missing ("No such file or directory"); a folder or symlink removed underneath (by a sync client, say), a file that could not be opened for reading and a failed read all came back as "Input/output error"; the extended attributes of a deleted file reported "Attribute not found".
- **Development**: the tests no longer read or write the app's keychain items, and `Scripts/test.sh` runs every test layer that needs no mount.

## v1.4.1 (2026-10-08) — Defense in Depth
- **Append-only flag**: `chflags uappnd` on a file in a vault left the file impossible to write. Setting the append-only flag is now refused ("Operation not supported"); a flag that is already set can still be cleared.
- **Command line**: `--password=…` printed the password back in its error message. It now gets the same notice as `--password`, and the value of an unknown `--option=value` is never printed.
- **Text fields**: inline predictions (suggested completions) are off in all text fields, the shown-password field included.
- **Tampered vault folders**: refused instead of being acted on: an extended attribute value of gigabytes planted in the encrypted folder (could crash the file system extension), scrypt settings in a planted `gocryptfs.conf` that cost many times the CPU of the largest normal setting, and path names ending in `..` that reached the folder above the encrypted folder of a `-plaintextnames` vault.
- **Engine**: read, write and truncate requests at offsets that do not fit a file are refused before anything is written. The mounted volume never sends them; other callers of the engine could overwrite the start of a file.

## v1.4.0 (2026-10-06) — Post-merge Review Fixes
- **plaintextnames vaults**: on vaults created with `-plaintextnames` (by upstream gocryptfs), `gocryptfs.conf` in the root could be deleted, replaced by a rename or changed through the mounted volume, which destroys the vault's key. It is now refused like upstream does (`EPERM`).
- **Error codes**: a file that is listed but cannot be opened for reading (permission denied, too many open files, a cloud placeholder that fails to download) reports the real error instead of "No such file or directory", which backup tools took for a file deleted mid-run.
- **Quitting**: with one volume busy and another failing to unmount for a different reason, forcing the busy one let the app quit with the other still mounted. The app now only quits when the mount table shows none of your volumes, and offers to force only when that can let it quit.
- **Mounting**: a vault whose `gocryptfs.conf` is a symlink into a mounted vault is refused, like a vault inside a mounted vault (mounting it hangs the system's file system service). The app no longer resolves mount points in its periodic mount check, which could freeze the window while the file system service was stuck.
- **Directory listings**: file names can no longer be chosen so that one of them is left out of directory listings.
- **New files**: a file created read-only or without read permission can always be written and read by the program that created it, also when its size is set before it is opened.
- **Renames**: a change to a file that a rename is replacing at the same moment no longer lands on the file that takes its name.

## v1.3.11 (2026-10-06) — Security Checklist Wrap-up
- **Copying read-only files**: copying a read-only file (mode 0444) into a vault failed with an I/O error and left an empty file behind. A new file now takes the writes of the open that created it, whatever its mode. Creating a vault inside a mounted vault failed the same way.
- **File attributes**: modification, access and creation times and flags (hidden, locked …) take effect instead of being silently dropped (`touch -t`, `cp -p`, `chflags`). Creation dates and flags of files on a mounted vault are shown correctly; they used to read as 1970 and none.
- **Directory listings**: listing a directory while other files are added or removed no longer skips or repeats the files that stay.
- **Error codes**: truncate, write and open report the real error (`ENOSPC`, `EFBIG`, `EPERM`, `ENOENT` …) instead of a generic I/O error.
- **Removed files that are still open**: attribute and extended-attribute changes go to that file, no longer to a new file that took over its name.
- **Extended attributes**: the target is resolved once through directory handles, so a directory swapped for a symlink (for example by a sync client) cannot redirect an attribute outside the vault.
- **Mounting**: a vault addressed through the `/System/Volumes/Data/…` spelling of its path is recognized as already mounted. A vault inside another mounted vault is refused: mounting it hung the system's file system service, external disks included, until the extension was killed. Vaults on long non-ASCII paths show as mounted. Vaults whose folders share a name get distinct default mount points.
- **Malicious gocryptfs.conf**: scrypt parameters that need more than 1 GiB of memory, or P above 16, are refused before anything is allocated. New vaults are capped at logN 20 to match.
- **Text fields**: system text replacement (such as "omw" → "On my way!") and the other typing substitutions are off in the app's text fields, so typing a password with "show password" on can no longer create a vault with a password you did not type.
- **Smaller fixes**: the extension no longer asks the engine for a copy of the scrypt hash; an overlong credential is refused instead of crashing; the iOS packaging script no longer uses shared `/tmp` paths.

## v1.3.10 (2026-10-05) — Security Review Follow-up
- **Unlinked and replaced files**: a file removed or overwritten by a rename while still open keeps its handles until it is closed. Writes no longer bring a deleted file back, or land in the file that took over its name (which could leave that file unreadable after a remount). New files are created exclusively, so two racing `O_EXCL` creates (lock files) can no longer both succeed.
- **Engine robustness**: writes beyond the end of a file pad the previous partial block; unmounting waits for in-flight operations before wiping keys; every C entry point recovers from internal panics; handle and volume IDs are never reused; `gocryptfs.diriv` is read with a size bound and without following symlinks; FIFOs planted in the ciphertext directory are refused instead of blocking; a rename no longer races with callbacks that read the renamed item's path.
- **Attributes and error codes**: attributes of a removed item report `ENOENT` instead of an empty set (which FSKit logged as a fault and turned into `EINVAL`); an unlinked file that is still open keeps answering `fstat`. `mkdir`, `rmdir`, `rename` and `unlink` return the real error (`EEXIST`, `ENOTEMPTY`, …) rather than a generic I/O error. `chmod` never follows a symlink out of the vault.
- **Quitting**: quitting unmounts only your own volumes and never forces on its own. If a volume is busy the app stays open and offers the same Force / Cancel choice as the other unmount paths.
- **Mounting**: a vault that is already mounted is refused even when addressed through a symlink or another path alias.
- **CLI**: unknown options are errors (a misspelled `--readonly` no longer mounts writable). `--password-stdin` refuses a terminal, rejects passwords over 4096 bytes instead of truncating them, and strips exactly one trailing newline. An interrupted mount (Ctrl-C) removes its Keychain credential.
- **Keychain hygiene**: stale credentials are found by enumerating the Keychain, including those of unregistered vaults; credentials younger than two minutes are left alone so the app cannot delete the credential of a CLI mount in progress. The extension no longer accepts a caller-chosen Keychain account.
- **Extended attributes**: attribute names are now encrypted with upstream gocryptfs's fixed IV, so xattrs interoperate with Linux gocryptfs. Attributes written by earlier versions remain readable and are converted when they are next written; nothing is rewritten in bulk. Versions up to 1.3.9 cannot read attributes written by this version (file contents are unaffected).
- **Mount point privacy**: the default mount root `~/Volumes` is created with mode 0700 and tightened to 0700 at mount time if it was open to other accounts (FSKit volumes are mounted with `noowners`, so only the path protects mounted files). The vault card and the CLI warn when a custom mount point is reachable by other users.
- **Visible password fields**: autocorrection is disabled in the plain-text password fields used by "show password".
- **Privacy and release scripts**: volume names and paths are logged as private. The release script verifies the provisioning profiles and signing identity and stops if they are missing.

## v1.3.9 (2026-10-04) — Data Integrity Fixes
- Share file IDs and content locks across handles for the same backing inode; zero truncation clears the shared ID before rewriting the header.
- Correct FSKit close modes to retain requested access, release unused handles, and preserve temporary I/O references.
- Truncate acquired writable handles using fd metadata; synchronize handle access and close without retaining the handle table lock.
- Invalidate directory fd caches after rename and rmdir to prevent writes or deletions affecting moved-away files. Add engine, extension, VaultCore, and remount regressions.

## v1.3.8 (2026-09-19) — Robustness & Architecture Enhancements
- **Mount Point Pre-flight Hint**: Added real-time non-intrusive warning in the vault card when a target mount directory already exists and is not empty or is a file.
- **Card Layout & Writable Toggle**: Added localized "Writable" label adjacent to the mount mode switch toggle, and placed "Mount Point" above "Encrypted Directory" for a more natural top-down workflow.
- **Typed Error Architecture**: Introduced `MountError` and `UnmountError` enums in `VaultCore` for structured, type-safe error handling and localization across the app and CLI.
- **Dual Mount State Sync**: Integrated `NSWorkspace` notifications (`didMountNotification`, `didUnmountNotification`) for instant sub-second UI updates when volumes are mounted or ejected via Finder, backed by periodic polling.
- **CLI Forced Unmount**: Added `-f` / `--force` flags to `GocryptKit umount` CLI command.
- **Zero-Byte File Read Fix**: Fixed engine I/O behavior on empty files to return EOF cleanly instead of erroring out.
- **Comprehensive Test Suite**: Added `RobustnessTests` covering block boundaries (0B, 4096B, 4097B), multi-threaded concurrent read/write, bit-rot/tampering rejection, and typed error parsing (108/108 tests passing).

## v1.3.7 (2026-09-19) — Unmount Reliability & UI Polish
- **Unmount Experience & Reliability**:
  - **Busy Volume Handling**: Fixed silent unmount failures on in-use volumes. When a vault has open file handles (e.g. media players or Finder), clicking Unmount in the main window now immediately presents an alert offering "Force Unmount", ensuring 100% parity with the menu bar tray.
  - **Auto-expand on Error**: Automatically expands the vault card and displays humanized error diagnostics and inline force-unmount controls if unmounting is cancelled or blocked.
  - **Mount Path Fallback**: Hardened mount point path resolution with automatic fallbacks for read-only suffixes (`_READ_ONLY`) and live kernel mount table queries.
- **UI & Layout**:
  - **Mount Mode Switch Toggle**: Upgraded the temporary read-only mount checkbox to an intuitive macOS native Switch toggle. Switching ON selects read-write mode ("Mount in read-write mode"), while switching OFF activates read-only mode ("Mount in read-only mode") with orange status indicators and instant mount button / path preview synchronizations.
  - **Password Error Positioning**: Fixed error message placement for failed unlocks (wrong password / masterkey). The warning banner is now displayed directly beneath the password input and automatically clears when typing a new password.
  - Moved the low-frequency "Name" (vault rename) input field to the very bottom of the card details, keeping high-frequency mount controls prominent.

## v1.3.6 (2026-09-19) — UI Polish & Localization Fixes
- **UI & Interaction**:
  - Moved the password input field, Mount button, and Read-Only checkbox to the very top of the expanded vault card for immediate keyboard focus and visual priority.
  - Moved the low-frequency "Name" (vault rename) input field to the very bottom of the card details.
  - Removed card-level keyboard focus highlight: eliminated distracting blue focus border overlays on vault tiles, restoring clean native dividers.
- **Localization**:
  - Fixed Caps Lock indicator bubble showing `"localized string not found"` by providing a full language fallback chain (`["zh-Hans", "zh-CN", "zh", "en"]`) and declaring `CFBundleLocalizations`.
  - Added localized strings for static 4-character password length validation and Caps Lock indicator.
- **Build & Quality**:
  - Full notarized & stapled DMG release (`GocryptKit-1.3.6.dmg`), passing all unit tests and 108 end-to-end assertions.

## v1.3.5 (2026-09-19) — Quality, Concurrency & Security Hardening
- **Security Hardening**:
  - Added secondary confirmation warning dialog when creating a vault with a weak password (<8 characters or weak strength), preventing accidental weak passphrases while keeping policy flexible.
  - Extended `OrphanReaper` to perform deep sweeping of temporary read-only session credentials (`mountctx:`) on app startup and termination.
  - Eliminated redundant facades (`KeychainHelper` and `KeychainReader`) to standardize directly on `VaultCore.KeychainStore`.
- **Concurrency & Reliability**:
  - Implemented async stream draining for child process stderr in `ProcessRunner` using Swift 6 thread-safe `LockedBuffer`, completely eliminating OS pipe deadlocks on outputs exceeding 64 KiB.
  - Consolidated duplicate timeout process runner logic from `MountManager` into `ProcessRunner`.
  - Enforced strict `@MainActor` thread safety for `MountManager.extensionStatus` and added thread-safe helper inspection to eliminate race conditions between background polling and UI rendering.
- **UI/UX & Localization**:
  - Clarified read-only mount options between persistent default configuration and temporary session-only mounts.
  - Added automatic recursive directory creation when specifying non-existent paths during vault initialization.
  - Fully localized macOS system menus (Edit, Window, Undo/Redo, Cut/Copy/Paste, Select All) in both English and Simplified Chinese.
  - Added keyboard focus (`.focusable()`) and Space key toggle for vault cards.
- **Verification**: 104 unit test assertions and 108 end-to-end integration test assertions passing with Apple Developer ID notarization and stapling.

## v1.3.4 — Dynamic Localization & Read-Only Regression
- Fixed cold-start language switching inconsistency by synchronizing `AppleLanguages` with app preferences.
- Added comprehensive E2E test assertions verifying read-only volume CRUD kernel-level blocking.

## v1.3.0 – v1.3.3 — Read-Only Finder Integration & Build Automation
- Ensured consistent `_READ_ONLY` volume naming in Finder sidebar and window titles via shared `MountContextStore` keychain intent.
- Added robust comma-separated task options parsing (`ro`, `rdonly`, `volname`) in FSKit volume loader.
- Automated release pipeline optimizations with notary submission retries and `create-dmg` headless fallback.

## v1.2.5 — Defense-in-Depth & Unmount Safety
- Added defensive `umount -f` force-unmount fallback on app termination to prevent lingering mountpoints.
- Added direct GitHub repository and documentation links to the standard About panel.

## v1.2.4 — Official Open-Source Release
- First public open-source release on GitHub ([maxing-labs/GocryptKit](https://github.com/maxing-labs/GocryptKit)) under GPL-3.0 with Apple App Store Exception.
- MenuBar companion enhancements: unmount debounce, mutual exclusion locks, and aggregated conflict dialog when multiple volumes encounter `EBUSY`.
- Flexible password policy: replaced hard blocking on short passwords with advisory warning badges.
- Translated all codebase technical comments to English.

## v1.2.0 — Architecture Decoupling & Review
- Refactored core modules to address code review findings and strengthen separation of concerns.

## v1.1.2 — Media Seek Stabilization & App Interception
- Fixed `EIO` (Input/output error) on large video file random seek and Python `pread` via Chunked Read Loop in Go C-API.
- Decoupled read and write file handles with independent reference counting and granular locks.
- Added app termination interception with safety prompts when active mounts exist.
- Fixed focus-stealing bug on unmount.

## v1.1.0 — Hardened Credential Protocol & App Refactoring
- Standardized on TLV-tagged credential protocol (Magic: `VCP1`) with strict length checks and trailing garbage rejection.
- Decomposed monolithic app views into `ContentView`, `VaultRowView`, `VaultRowViewModel`, and `MountManager`.
- Expanded unit test suite to 90 tests.

## v1.0.1 — MenuBar Integration & Auto-Focus
- Introduced MenuBar status item with dynamic lock state icons (`lock.open.fill` / `lock.fill`).
- Added automatic focus on password field upon vault row expansion.
- Completed stress testing on large video and binary payloads.

## v1.0.0 — Project Rebranding & Initial Milestone
- Project officially renamed from `GocryptfsKit` to `GocryptKit`.
- Packaged official notarized macOS DMG distribution.
- Completed comprehensive security audits, architecture documentation (`AGENTS.md`), and clean export tooling.

## v0.2.3 — Deep Security Hardening
- Introduced TLV-tagged Keychain protocol to prevent type confusion between passwords and scrypt hashes.
- Enforced consume-on-mount credential lifecycle (`deleteCredential`).
- Implemented pure-logic `OrphanReaper` algorithm for cleaning up stale credentials.
- Explicit in-memory secret scrubbing via `memset_s`.
- Removed plaintext `--password` CLI argument in favor of masked terminal input and `--password-stdin`.
- Enforced POSIX `0600` permissions on registry files.

## v0.2.2 — Internationalization & UI Enhancements
- Added English and Simplified Chinese localization.
- Added password visibility toggle.
- Explored iOS/iPadOS client architecture prototype.

## v0.2.1 — Resilience & Extension State Fixes
- Decoupled release smoke-tests from live extension state.
- Resolved FSKit probing issues while volumes were mounted.

## v0.2.0 — Multi-Vault Management & App Branding
- Multi-vault list UI in SwiftUI.
- Dedicated App Icon design (folder-key glyph).
- Improved FSKit module status detection via `pluginkit`.

## v0.1.0 — Initial Public Milestone
- First distributable notarized DMG release.
- Native FSKit read-write gocryptfs volume, host app, and CLI (`init`, `mount`, `umount`, `status`).
- Developer ID release pipeline with inside-out code signing and initial 87-assertion E2E test suite.

## Pre-Release Milestones (M0 – M2.5)
- **M2.5**: Hardened credential channel between host and FSKit extension; interactive masked CLI input and `--password-stdin` pipeline; initial bilingual localization.
- **M2**: Full read-write filesystem mutations; native macOS extended attributes (`xattr`) encrypted via EME + DirIV (AES-GCM); `.fseventsd/no_log` suppression.
- **M1.5**: Reproducible Developer ID code signing pipeline; initial Apple Notarization (`notarytool`) and stapling automation; authoring of the end-to-end integration test suite over real media files (PDF, MP3, MP4, text).
- **M1**: Read-only FSKit volume implementation; successfully mounting and decrypting gocryptfs vaults into Finder without drivers or kernel extensions.
- **M0.5**: FSKit registration, lifecycle, and filesystem module (`FSFileSystem`) integration spike.
- **M0**: Core engine build (`libgocryptfs` darwin/arm64 c-archive packaged into `libgocryptfs.xcframework`), `VaultCore` Swift package foundation, and `vaultctl` test CLI.
