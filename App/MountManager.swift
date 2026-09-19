import Foundation
import VaultCore
import OSLog

private let logger = Logger(subsystem: "com.xwei.GocryptKit", category: "MountManager")

@Observable
final class MountManager: @unchecked Sendable {
    static let shared = MountManager()

    /// Operational availability of the FSKit module from the kernel's perspective.
    /// Initialized to `.unknown`: probing takes 1-2 seconds, and we avoid guessing beforehand.
    @MainActor
    var extensionStatus: FSModuleStatus = .unknown
    @MainActor
    var isExtensionEnabled: Bool { extensionStatus == .enabled }

    static let extensionIdentifier = "com.xwei.GocryptfsKit.AppEx"

    private let activeMountingLock = NSLock()
    private var activeMountingKeys = Set<String>()

    private func recordActiveMount(_ canonical: String) {
        activeMountingLock.lock()
        activeMountingKeys.insert(canonical)
        activeMountingLock.unlock()
    }

    private func removeActiveMount(_ canonical: String) {
        activeMountingLock.lock()
        activeMountingKeys.remove(canonical)
        activeMountingLock.unlock()
    }

    private func getInFlightMounts() -> Set<String> {
        activeMountingLock.lock()
        defer { activeMountingLock.unlock() }
        return activeMountingKeys
    }

    init() {}

    /// Check the FSKit extension's availability without disturbing running
    /// volumes. Uses `pluginkit` to verify registration, then assumes the
    /// module is enabled. If the module turns out to be disabled, the
    /// actual mount failure will update the status via `noteMountFailure`.
    func checkExtensionStatus() {
        let newStatus: FSModuleStatus
        if !MountTable.gocryptfsMounts().isEmpty {
            newStatus = .enabled
        } else {
            newStatus = Self.probeExtensionStatus()
        }

        if Thread.isMainThread {
            MainActor.assumeIsolated {
                self.extensionStatus = newStatus
            }
        } else {
            DispatchQueue.main.async {
                self.extensionStatus = newStatus
            }
        }
    }

    private static func probeExtensionStatus() -> FSModuleStatus {
        guard let listing = ProcessRunner.runCapturingOutput(
            "/usr/bin/pluginkit", ["-m", "-v", "-i", extensionIdentifier]
        ) else { return .unknown }

        guard FSModuleProbe.isRegistered(pluginkitOutput: listing) else {
            return .notRegistered
        }

        return .enabled
    }

    /// If mount failure output explicitly states "is disabled", update the cached status immediately —
    /// relieving the user from manually triggering a refresh to see the true state.
    func noteMountFailure(_ message: String) {
        if FSModuleProbe.interpret(mountStderr: message) == .disabled {
            if Thread.isMainThread {
                MainActor.assumeIsolated {
                    self.extensionStatus = .disabled
                }
            } else {
                DispatchQueue.main.async {
                    self.extensionStatus = .disabled
                }
            }
        }
    }

    private func prepareCredential(cipherDir: URL, password: String) throws {
        // 1. Verify gocryptfs.conf
        let confURL = cipherDir.appendingPathComponent("gocryptfs.conf")
        guard FileManager.default.fileExists(atPath: confURL.path) else {
            throw VaultError.configNotFound
        }

        // 2. Validate password with GocryptfsEngine and obtain scrypt hash
        var scryptHash: Data? = nil
        let engine = try GocryptfsEngine(cipherDir: cipherDir, credential: .password(password), returnedScryptHash: &scryptHash)
        engine.shutdown()

        // 3. Store credential into shared Keychain
        let payload: VaultCredentialPayload
        if let scryptHash {
            payload = .scryptHash(scryptHash)
        } else {
            payload = .password(password)
        }
        let credentialData = payload.serialize()
        let accountKey = Vault.canonicalKey(path: cipherDir.path)
        let status = KeychainStore.saveCredentialStatus(account: accountKey, data: credentialData)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: [
                NSLocalizedDescriptionKey: "Could not store the vault credential in the Keychain (OSStatus \(status)). The extension cannot unlock the volume without it."
            ])
        }
    }

    private var isExtensionExplicitlyDisabled: Bool {
        if Thread.isMainThread {
            return MainActor.assumeIsolated { extensionStatus == .disabled }
        } else {
            return DispatchQueue.main.sync { extensionStatus == .disabled }
        }
    }

    /// Asynchronous mount with non-blocking retry delays (for GUI).
    func mountVault(cipherDir: URL, mountPoint: URL, password: String, readOnly: Bool = false) async throws {
        let targetMountPoint = readOnly ? URL(fileURLWithPath: Vault.readOnlyMountPoint(for: mountPoint.path)) : mountPoint
        let canonical = Vault.canonicalKey(path: cipherDir.path)
        recordActiveMount(canonical)
        defer {
            removeActiveMount(canonical)
        }

        // Ensure mountpoint directory exists
        if !FileManager.default.fileExists(atPath: targetMountPoint.path) {
            try FileManager.default.createDirectory(at: targetMountPoint, withIntermediateDirectories: true)
        }

        var lastError: Error?
        for attempt in 1...Self.mountAttempts {
            do {
                try prepareCredential(cipherDir: cipherDir, password: password)
                try Self.runMount(cipherDir: cipherDir, mountPoint: targetMountPoint, readOnly: readOnly)
                MountRecordStore.rememberCipherDir(cipherDir, for: targetMountPoint)
                return
            } catch {
                lastError = error
                noteMountFailure(error.localizedDescription)
                if isExtensionExplicitlyDisabled {
                    break
                }
                logger.info("mount attempt \(attempt, privacy: .public) of \(Self.mountAttempts, privacy: .public) failed")
                if attempt < Self.mountAttempts {
                    try? await Task.sleep(nanoseconds: UInt64(Self.mountRetryDelay * 1_000_000_000))
                }
            }
        }

        // Mount never succeeded; consume/delete the ephemeral credential
        _ = KeychainStore.deleteCredential(account: canonical)
        throw lastError ?? VaultError.ioError(EIO)
    }

    /// Synchronous mount wrapper for CLI / script invocations.
    func mountVaultSync(cipherDir: URL, mountPoint: URL, password: String, readOnly: Bool = false) throws {
        let targetMountPoint = readOnly ? URL(fileURLWithPath: Vault.readOnlyMountPoint(for: mountPoint.path)) : mountPoint
        let canonical = Vault.canonicalKey(path: cipherDir.path)

        recordActiveMount(canonical)
        defer {
            removeActiveMount(canonical)
        }

        // Ensure mountpoint directory exists
        if !FileManager.default.fileExists(atPath: targetMountPoint.path) {
            try FileManager.default.createDirectory(at: targetMountPoint, withIntermediateDirectories: true)
        }

        var lastError: Error?
        for attempt in 1...Self.mountAttempts {
            do {
                try prepareCredential(cipherDir: cipherDir, password: password)
                try Self.runMount(cipherDir: cipherDir, mountPoint: targetMountPoint, readOnly: readOnly)
                MountRecordStore.rememberCipherDir(cipherDir, for: targetMountPoint)
                return
            } catch {
                lastError = error
                noteMountFailure(error.localizedDescription)
                if isExtensionExplicitlyDisabled {
                    break
                }
                logger.info("mount attempt \(attempt, privacy: .public) of \(Self.mountAttempts, privacy: .public) failed")
                if attempt < Self.mountAttempts {
                    Thread.sleep(forTimeInterval: Self.mountRetryDelay)
                }
            }
        }

        // Mount never succeeded; consume/delete the ephemeral credential
        _ = KeychainStore.deleteCredential(account: canonical)
        throw lastError ?? VaultError.ioError(EIO)
    }

    private static let mountAttempts = 3
    private static let mountRetryDelay: TimeInterval = 2

    private static func runMount(cipherDir: URL, mountPoint: URL, readOnly: Bool = false) throws {
        let volName = mountPoint.lastPathComponent.replacingOccurrences(of: ",", with: "_")
        let context = MountContext(
            volumeName: volName,
            isReadOnly: readOnly,
            mountPoint: mountPoint.path
        )
        MountContextStore.save(context, for: cipherDir.path)
        defer {
            MountContextStore.delete(for: cipherDir.path)
        }

        var args = ["-t", "gocryptfs"]
        var mountOptions: [String] = []
        if readOnly {
            args.append("-r")
            mountOptions.append("ro")
            mountOptions.append("rdonly")
        }
        mountOptions.append("volname=\(volName)")
        args.append(contentsOf: ["-o", mountOptions.joined(separator: ",")])
        args.append(contentsOf: [cipherDir.path, mountPoint.path])
        let (status, errMsg) = try ProcessRunner.runWithTimeout(
            executable: "/sbin/mount",
            arguments: args
        )

        if status != 0 {
            throw NSError(domain: "GocryptfsMountError", code: Int(status), userInfo: [
                NSLocalizedDescriptionKey: "Mount failed (code \(status)): \(errMsg)"
            ])
        }
    }

    /// Sweep Keychain entries that belong to vaults no longer mounted, protecting actively mounting vaults.
    func reapOrphanCredentials(knownVaults: [Vault]) {
        let currentMounts = Set(MountTable.gocryptfsMounts().keys)
        let inFlight = getInFlightMounts()

        let orphans = OrphanReaper.accountsToReap(
            knownVaultPaths: knownVaults.map(\.cipherDirPath),
            mountedCanonicalKeys: currentMounts.union(inFlight),
            includeMountContext: true
        )
        for key in orphans {
            KeychainStore.deleteCredential(account: key)
        }
    }

    func unmountVault(mountPoint: URL, force: Bool = false) throws {
        let args = force ? ["-f", mountPoint.path] : [mountPoint.path]
        let (status, errMsg) = try ProcessRunner.runWithTimeout(
            executable: "/sbin/umount",
            arguments: args
        )

        if status != 0 {
            throw NSError(domain: "GocryptfsUnmountError", code: Int(status), userInfo: [
                NSLocalizedDescriptionKey: "Unmount failed (code \(status)): \(errMsg)"
            ])
        }

        if let cipherPath = MountRecordStore.forgetCipherDir(for: mountPoint) {
            _ = KeychainStore.deleteCredential(account: cipherPath)
            _ = MountContextStore.delete(for: cipherPath)
        } else {
            logger.info("unmount: no recorded cipher directory, Keychain credential left in place")
        }

        // Clean up empty temporary mount point directory created for read-only mounts
        if mountPoint.lastPathComponent.hasSuffix(Vault.readOnlySuffix) {
            if let contents = try? FileManager.default.contentsOfDirectory(atPath: mountPoint.path), contents.isEmpty {
                try? FileManager.default.removeItem(at: mountPoint)
            }
        }
    }
}
