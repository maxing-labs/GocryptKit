import Foundation
import Observation
import VaultCore

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

        Task.detached(priority: .userInitiated) {
            do {
                try await MountManager.shared.mountVault(
                    cipherDir: cipherDir,
                    mountPoint: mountPoint,
                    password: pwd,
                    readOnly: ro
                )
                await MainActor.run {
                    self.isBusy = false
                    store.refreshMountState()
                }
            } catch {
                await MainActor.run {
                    self.isBusy = false
                    self.errorMessage = Self.humanize(error)
                    MountManager.shared.noteMountFailure(error.localizedDescription)
                    store.refreshMountState()
                }
            }
        }
    }

    func performUnmount(vault: Vault, actualMountPoint: String?, store: VaultStore) {
        errorMessage = nil
        canForceUnmount = false
        isBusy = true
        let target = URL(fileURLWithPath: actualMountPoint ?? vault.mountPointPath)

        Task.detached(priority: .userInitiated) {
            do {
                try MountManager.shared.unmountVault(mountPoint: target)
                await MainActor.run {
                    self.isBusy = false
                    self.canForceUnmount = false
                    store.refreshMountState()
                }
            } catch {
                await MainActor.run {
                    self.isBusy = false
                    self.errorMessage = Self.humanizeUnmountError(error)
                    let raw = error.localizedDescription.lowercased()
                    if raw.contains("busy") || raw.contains("in use") {
                        self.canForceUnmount = true
                    }
                    store.refreshMountState()
                }
            }
        }
    }

    func performForceUnmount(vault: Vault, actualMountPoint: String?, store: VaultStore) {
        errorMessage = nil
        isBusy = true
        let target = URL(fileURLWithPath: actualMountPoint ?? vault.mountPointPath)

        Task.detached(priority: .userInitiated) {
            do {
                try MountManager.shared.unmountVault(mountPoint: target, force: true)
                await MainActor.run {
                    self.isBusy = false
                    self.canForceUnmount = false
                    store.refreshMountState()
                }
            } catch {
                await MainActor.run {
                    self.isBusy = false
                    self.errorMessage = Self.humanizeUnmountError(error)
                    store.refreshMountState()
                }
            }
        }
    }

    static func humanize(_ error: Error) -> String {
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
        let raw = error.localizedDescription
        if raw.contains("Resource busy") {
            return loc("Volume is in use by another application. Please close open files/Finder windows and try again.")
        }
        return raw
    }
}
