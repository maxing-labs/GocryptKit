import Foundation

/// An encrypted vault registered in the application.
///
/// Holds only facts configured by the user: ciphertext path, intended mount point, and display name.
/// **Mount state is intentionally excluded**: that is a system-level fact that must always be queried
/// live from `MountTable`. Persisting mount status locally leads to desynchronization (e.g. volumes
/// mounted via CLI, unmounted in Finder, or surviving app crashes).
public struct Vault: Codable, Identifiable, Hashable, Sendable {
    public let id: UUID
    /// Display name. Defaults to the last path component of the ciphertext directory; user-editable.
    public var name: String
    /// Ciphertext directory path (containing gocryptfs.conf). Standardized absolute path.
    public var cipherDirPath: String
    /// Target mount point chosen by user. May not exist yet; created during mount.
    public var mountPointPath: String
    /// Whether this vault should be mounted in read-only mode by default.
    public var isReadOnlyDefault: Bool

    public init(id: UUID = UUID(), name: String, cipherDirPath: String, mountPointPath: String, isReadOnlyDefault: Bool = false) {
        self.id = id
        self.name = name
        self.cipherDirPath = cipherDirPath
        self.mountPointPath = mountPointPath
        self.isReadOnlyDefault = isReadOnlyDefault
    }

    enum CodingKeys: String, CodingKey {
        case id, name, cipherDirPath, mountPointPath, isReadOnlyDefault
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decode(UUID.self, forKey: .id)
        self.name = try container.decode(String.self, forKey: .name)
        self.cipherDirPath = try container.decode(String.self, forKey: .cipherDirPath)
        self.mountPointPath = try container.decode(String.self, forKey: .mountPointPath)
        self.isReadOnlyDefault = try container.decodeIfPresent(Bool.self, forKey: .isReadOnlyDefault) ?? false
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(cipherDirPath, forKey: .cipherDirPath)
        try container.encode(mountPointPath, forKey: .mountPointPath)
        try container.encode(isReadOnlyDefault, forKey: .isReadOnlyDefault)
    }

    public var cipherDirURL: URL { URL(fileURLWithPath: cipherDirPath) }
    public var mountPointURL: URL { URL(fileURLWithPath: mountPointPath) }

    public static let readOnlySuffix = "_READ_ONLY"

    public var readOnlyMountPointPath: String {
        Self.readOnlyMountPoint(for: mountPointPath)
    }

    public var readOnlyMountPointURL: URL {
        URL(fileURLWithPath: readOnlyMountPointPath)
    }

    public static func readOnlyMountPoint(for path: String) -> String {
        let normalized = normalize(path: path)
        if normalized.hasSuffix(readOnlySuffix) {
            return normalized
        }
        return normalized + readOnlySuffix
    }

    /// Standardizes path by resolving `~`, `.`, `..`, and duplicate slashes. **Use this for persistence.**
    /// Does not resolve symlinks: that requires the directory to physically exist on disk,
    /// whereas external drives might not be mounted yet at registration time.
    public static func normalize(path: String) -> String {
        let expanded = (path as NSString).expandingTildeInPath
        return (expanded as NSString).standardizingPath
    }

    /// Key used to determine identity equivalence between paths. **Use this for comparison, never for persistence.**
    ///
    /// Resolves symlinks in addition to normalization because kernel-reported mount paths are resolved:
    /// e.g. user configures `/tmp/x` while the mount table reports `/private/tmp/x`. Direct string
    /// comparisons will never match.
    ///
    /// We deliberately use POSIX `realpath(3)` instead of `URL.resolvingSymlinksInPath`.
    /// `resolvingSymlinksInPath` strips leading `/private` only when the path physically exists.
    /// Consequently, it produces diverging results for `/private/tmp/existing` vs `/private/tmp/nonexistent`,
    /// making path equality dependent on directory existence. `realpath(3)` consistently converges
    /// to the canonical destination.
    ///
    /// If the path does not exist, `realpath` fails and falls back to `normalize` — non-existent
    /// paths cannot be mounted or found in the mount table anyway.
    public static func canonicalKey(path: String) -> String {
        let normalized = normalize(path: path)
        guard let resolved = realpath(normalized, nil) else { return normalized }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    /// Derives default vault configuration: name from ciphertext directory, mount point at ~/Volumes/<name>.
    public static func makeDefault(cipherDir: URL) -> Vault {
        let normalized = normalize(path: cipherDir.path)
        let name = (normalized as NSString).lastPathComponent
        #if os(macOS)
        let mountPoint = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Volumes")
            .appendingPathComponent(name)
        #else
        let baseDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first ?? URL(fileURLWithPath: NSTemporaryDirectory())
        let mountPoint = baseDir.appendingPathComponent(name)
        #endif
        return Vault(name: name,
                     cipherDirPath: normalized,
                     mountPointPath: normalize(path: mountPoint.path))
    }
}

public enum VaultRegistryError: LocalizedError, Equatable {
    case notAVault(String)
    case duplicate(existingName: String)

    public var errorDescription: String? {
        switch self {
        case .notAVault(let path):
            return "No gocryptfs.conf found in \(path); not a gocryptfs vault."
        case .duplicate(let name):
            return "This encrypted directory is already in the list (\(name))."
        }
    }
}
