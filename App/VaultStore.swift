import Foundation
import Observation
import OSLog
import VaultCore

private let logger = Logger(subsystem: "com.xwei.GocryptKit", category: "VaultStore")

/// The single source of truth behind the UI: a list of registered vaults, plus a live-queried mount table.
///
/// These two sets of data are intentionally stored separately. The list represents user intent (persisted to disk),
/// while the mount table represents system reality (queried live from the kernel). Persisting "isMounted"
/// to disk inevitably causes drift from ground truth.
@MainActor
@Observable
final class VaultStore {
    private(set) var vaults: [Vault] = []
    /// Keyed by `Vault.canonicalKey` of the ciphertext directory. Mutated solely by `refreshMountState()`.
    private(set) var mounts: [String: MountTable.Entry] = [:]

    /// When a user clicks an unmounted vault from an external entry (e.g., status bar menu), tracks the intent to expand the row and focus the password field.
    var requestedFocusVaultID: UUID?

    func requestFocus(for vaultID: UUID) {
        requestedFocusVaultID = vaultID
    }

    func clearFocus() {
        requestedFocusVaultID = nil
    }

    private let storeURL: URL?

    init(storeURL: URL? = try? VaultRegistry.defaultStoreURL()) {
        self.storeURL = storeURL
        reload()
        refreshMountState()
    }

    // MARK: - Disk Persistence

    private func reload() {
        guard let storeURL else { return }
        do {
            vaults = try VaultRegistry.load(from: storeURL).vaults
        } catch {
            // Inability to read the list should not block user workflow: fall back to an empty list, allowing re-registration.
            // Avoid overwriting the file on disk in case it can be manually recovered.
            logger.error("Failed to read vault list: \(error.localizedDescription, privacy: .public)")
            vaults = []
        }
    }

    private func persist() {
        guard let storeURL else { return }
        do {
            try VaultRegistry(vaults: vaults).save(to: storeURL)
        } catch {
            logger.error("Failed to save vault list: \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: - Mount Status

    /// Re-reads the mount table from the kernel. Lightweight (single getfsstat), safe to call frequently.
    func refreshMountState() {
        mounts = MountTable.gocryptfsMounts()
        MountManager.shared.reapOrphanCredentials(knownVaults: vaults)
    }

    func isMounted(_ vault: Vault) -> Bool {
        mounts[Vault.canonicalKey(path: vault.cipherDirPath)] != nil
    }

    /// Actual mount point. May diverge from registered path (e.g., if mounted elsewhere via CLI).
    func actualMountPoint(_ vault: Vault) -> String? {
        mounts[Vault.canonicalKey(path: vault.cipherDirPath)]?.mountPoint
    }

    var mountedCount: Int {
        vaults.filter { isMounted($0) }.count
    }

    // MARK: - CRUD Operations

    @discardableResult
    func addExisting(cipherDir: URL) throws -> Vault {
        var registry = VaultRegistry(vaults: vaults)
        let vault = try registry.add(cipherDir: cipherDir)
        vaults = registry.vaults
        persist()
        return vault
    }

    @discardableResult
    func addCreated(cipherDir: URL) -> Vault {
        var registry = VaultRegistry(vaults: vaults)
        let vault = registry.addCreated(cipherDir: cipherDir)
        vaults = registry.vaults
        persist()
        return vault
    }

    func remove(_ vault: Vault) {
        var registry = VaultRegistry(vaults: vaults)
        registry.remove(id: vault.id)
        vaults = registry.vaults
        persist()
    }

    func update(_ vault: Vault) {
        var registry = VaultRegistry(vaults: vaults)
        registry.update(vault)
        vaults = registry.vaults
        persist()
    }

    func rename(_ vault: Vault, to name: String) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != vault.name else { return }
        var copy = vault
        copy.name = trimmed
        update(copy)
    }

    func setMountPoint(_ vault: Vault, to path: String) {
        let normalized = Vault.normalize(path: path)
        guard normalized != vault.mountPointPath else { return }
        var copy = vault
        copy.mountPointPath = normalized
        update(copy)
    }
}
