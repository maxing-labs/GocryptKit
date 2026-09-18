import Foundation

/// Registry of user-configured vaults and its disk representation.
///
/// Pure value semantics, no singletons, no global state. Read and write operations
/// take explicit URLs, allowing tests to run entirely within temporary directories
/// without touching real user Application Support.
public struct VaultRegistry: Codable, Equatable, Sendable {
    public private(set) var vaults: [Vault]

    public init(vaults: [Vault] = []) {
        self.vaults = vaults
    }

    // MARK: - Query

    /// Finds a registered vault by ciphertext directory path. De-duplication uses `canonicalKey`,
    /// ensuring `/tmp/x` and `/private/tmp/x` resolve to the same vault.
    public func vault(forCipherDir path: String) -> Vault? {
        let target = Vault.canonicalKey(path: path)
        return vaults.first { Vault.canonicalKey(path: $0.cipherDirPath) == target }
    }

    public func contains(cipherDir path: String) -> Bool {
        vault(forCipherDir: path) != nil
    }

    // MARK: - Mutation

    /// Registers an existing vault. Rejects directories without gocryptfs.conf early,
    /// preventing invalid configurations from failing later during mount.
    @discardableResult
    public mutating func add(cipherDir: URL, fileManager: FileManager = .default) throws -> Vault {
        let normalized = Vault.normalize(path: cipherDir.path)
        let conf = (normalized as NSString).appendingPathComponent("gocryptfs.conf")
        guard fileManager.fileExists(atPath: conf) else {
            throw VaultRegistryError.notAVault(normalized)
        }
        if let existing = vault(forCipherDir: normalized) {
            throw VaultRegistryError.duplicate(existingName: existing.name)
        }
        let vault = Vault.makeDefault(cipherDir: URL(fileURLWithPath: normalized))
        vaults.append(vault)
        return vault
    }

    /// Registers a newly created vault by this app. Skips duplicate checks other than
    /// existing paths since creation workflow guarantees a fresh directory.
    @discardableResult
    public mutating func addCreated(cipherDir: URL) -> Vault {
        let normalized = Vault.normalize(path: cipherDir.path)
        if let existing = vault(forCipherDir: normalized) { return existing }
        let vault = Vault.makeDefault(cipherDir: URL(fileURLWithPath: normalized))
        vaults.append(vault)
        return vault
    }

    /// Removes a vault from the list. **Only modifies the registry; disk data is untouched.**
    public mutating func remove(id: UUID) {
        vaults.removeAll { $0.id == id }
    }

    /// Replaces a vault in-place (e.g. rename or updated mount point). No-op if ID does not match.
    public mutating func update(_ vault: Vault) {
        guard let index = vaults.firstIndex(where: { $0.id == vault.id }) else { return }
        vaults[index] = vault
    }

    // MARK: - Persistence

    /// Default persistence path: ~/Library/Application Support/GocryptKit/vaults.json.
    /// Host app is non-sandboxed, so this resolves directly to user home.
    public static func defaultStoreURL(fileManager: FileManager = .default) throws -> URL {
        let base = try fileManager.url(for: .applicationSupportDirectory,
                                       in: .userDomainMask,
                                       appropriateFor: nil,
                                       create: true)
        let dir = base.appendingPathComponent("GocryptKit", isDirectory: true)
        try fileManager.createDirectory(at: dir, withIntermediateDirectories: true)
        let targetURL = dir.appendingPathComponent("vaults.json")

        // Migrate legacy GocryptfsKit configuration if present and new config not yet created
        if !fileManager.fileExists(atPath: targetURL.path) {
            let legacyURL = base.appendingPathComponent("GocryptfsKit", isDirectory: true).appendingPathComponent("vaults.json")
            if fileManager.fileExists(atPath: legacyURL.path) {
                try? fileManager.copyItem(at: legacyURL, to: targetURL)
            }
        }

        return targetURL
    }

    /// Loads registry from disk. Returns an empty registry if file does not exist (first run is not an error).
    public static func load(from url: URL, fileManager: FileManager = .default) throws -> VaultRegistry {
        guard fileManager.fileExists(atPath: url.path) else { return VaultRegistry() }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(VaultRegistry.self, from: data)
    }

    /// Persists registry atomically. Writes to temporary file before atomic swap
    /// to avoid partial writes during sudden power loss.
    public func save(to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(self)
        try data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
