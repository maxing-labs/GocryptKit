import AppKit
import Foundation
import Observation
import VaultCore

@MainActor
@Observable
final class VaultRowViewModel: @unchecked Sendable {
    var isBusy: Bool = false
    var errorMessage: String?
    var canForceUnmount: Bool = false

    func performMount(vault: Vault, password: String, readOnly: Bool = false, store: VaultStore) {
        guard !password.isEmpty else { return }
        errorMessage = nil
        canForceUnmount = false
        isBusy = true
        let cipherDir = vault.cipherDirURL
        let mountPoint = readOnly ? vault.readOnlyMountPointURL : vault.mountPointURL
        let pwd = password
        let ro = readOnly

        Task {
            do {
                try await MountManager.shared.mountVault(
                    cipherDir: cipherDir,
                    mountPoint: mountPoint,
                    password: pwd,
                    readOnly: ro
                )
                self.isBusy = false
                store.refreshMountState()
            } catch {
                self.isBusy = false
                self.errorMessage = Self.humanize(error)
                MountManager.shared.noteMountFailure(error.localizedDescription)
                store.refreshMountState()
            }
        }
    }

    func performUnmount(
        vault: Vault,
        actualMountPoint: String?,
        store: VaultStore,
        onExpand: (@MainActor () -> Void)? = nil
    ) {
        errorMessage = nil
        canForceUnmount = false
        isBusy = true
        let resolvedPath = actualMountPoint
            ?? store.actualMountPoint(vault)
            ?? (store.isReadOnly(vault) ? vault.readOnlyMountPointPath : nil)
            ?? vault.mountPointPath
        let target = URL(fileURLWithPath: resolvedPath)

        Task {
            do {
                try await Task.detached(priority: .userInitiated) {
                    try MountManager.shared.unmountVault(mountPoint: target)
                }.value
                self.isBusy = false
                self.canForceUnmount = false
                store.refreshMountState()
            } catch {
                self.isBusy = false
                self.errorMessage = Self.humanizeUnmountError(error)
                let isBusy = (error as? UnmountError)?.isBusy ?? error.localizedDescription.lowercased().contains("busy")
                if isBusy {
                    self.canForceUnmount = true
                }
                store.refreshMountState()

                if isBusy {
                    let alert = NSAlert()
                    alert.alertStyle = .warning
                    alert.messageText = loc("Volume In Use")
                    alert.informativeText = loc("Vault \"\(vault.name)\" is currently in use by another application. Please close related files or Finder windows and try again.")
                    alert.addButton(withTitle: loc("Cancel"))
                    alert.addButton(withTitle: loc("Force Unmount"))

                    NSApp.activate(ignoringOtherApps: true)
                    let response = alert.runModal()
                    if response == .alertSecondButtonReturn {
                        self.performForceUnmount(vault: vault, actualMountPoint: resolvedPath, store: store)
                    } else {
                        onExpand?()
                    }
                } else {
                    onExpand?()
                    let alert = NSAlert()
                    alert.alertStyle = .warning
                    alert.messageText = loc("Unmount Failed")
                    alert.informativeText = Self.humanizeUnmountError(error)
                    NSApp.activate(ignoringOtherApps: true)
                    alert.runModal()
                }
            }
        }
    }

    func performForceUnmount(vault: Vault, actualMountPoint: String?, store: VaultStore) {
        errorMessage = nil
        isBusy = true
        let resolvedPath = actualMountPoint
            ?? store.actualMountPoint(vault)
            ?? (store.isReadOnly(vault) ? vault.readOnlyMountPointPath : nil)
            ?? vault.mountPointPath
        let target = URL(fileURLWithPath: resolvedPath)

        Task {
            do {
                try await Task.detached(priority: .userInitiated) {
                    try MountManager.shared.unmountVault(mountPoint: target, force: true)
                }.value
                self.isBusy = false
                self.canForceUnmount = false
                store.refreshMountState()
            } catch {
                self.isBusy = false
                self.errorMessage = Self.humanizeUnmountError(error)
                store.refreshMountState()

                let failAlert = NSAlert()
                failAlert.alertStyle = .critical
                failAlert.messageText = loc("Force Unmount Failed")
                failAlert.informativeText = error.localizedDescription
                NSApp.activate(ignoringOtherApps: true)
                failAlert.runModal()
            }
        }
    }

    static func humanize(_ error: Error) -> String {
        if let mountError = error as? MountError {
            switch mountError {
            case .extensionDisabled:
                return loc("FSKit extension is disabled by system; cannot mount. Go to System Settings → General → Login Items & Extensions → File System Extensions and enable GocryptKit, then try again.")
            case .extensionStartingUp:
                return loc("Extension is still starting up (known cold start behavior). Please click Mount again.")
            case .permissionDenied:
                return loc("Permission denied accessing vault or mount directory.")
            case .pathNotFound:
                return loc("Vault directory or mountpoint does not exist.")
            case .busyOrAlreadyMounted:
                return loc("Mount point is already mounted or busy.")
            case .invalidPasswordOrMasterKey:
                return loc("Authentication failed: invalid password or masterkey.")
            case .mountPointNotEmpty:
                return loc("Target mount directory is not empty.")
            case .generic(let code, let message):
                let useful = message
                    .split(separator: "\n")
                    .filter { !$0.contains("/Library/Filesystems/gocryptfs.fs") }
                    .joined(separator: "\n")
                let text = useful.isEmpty ? message : useful
                return code != 0 ? "\(text) (code \(code))" : text
            }
        }

        let raw = error.localizedDescription
        if FSModuleProbe.interpret(mountStderr: raw) == .disabled {
            return loc("FSKit extension is disabled by system; cannot mount. Go to System Settings → General → Login Items & Extensions → File System Extensions and enable GocryptKit, then try again.")
        }
        if raw.contains("Couldn't communicate with a helper application") {
            return loc("Extension is still starting up (known cold start behavior). Please click Mount again.")
        }
        if raw.contains("Permission denied") {
            return loc("Permission denied accessing vault or mount directory.")
        }
        if raw.contains("No such file or directory") {
            return loc("Vault directory or mountpoint does not exist.")
        }
        if raw.contains("Resource busy") || raw.contains("already mounted") {
            return loc("Mount point is already mounted or busy.")
        }
        // Retain other errors, stripping old mount helper fallback noise
        let useful = raw
            .split(separator: "\n")
            .filter { !$0.contains("/Library/Filesystems/gocryptfs.fs") }
            .joined(separator: "\n")
        return useful.isEmpty ? raw : useful
    }

    static func humanizeUnmountError(_ error: Error) -> String {
        if let unmountError = error as? UnmountError {
            switch unmountError {
            case .busy:
                return loc("Volume is in use by another application. Please close open files/Finder windows and try again.")
            case .generic(_, let message):
                return message
            }
        }

        let raw = error.localizedDescription
        if raw.contains("Resource busy") {
            return loc("Volume is in use by another application. Please close open files/Finder windows and try again.")
        }
        return raw
    }
}
