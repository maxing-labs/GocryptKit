import Foundation
import OSLog

private let logger = Logger(subsystem: "com.xwei.GocryptKit", category: "MountContextStore")

/// Ephemeral mount intention exchanged between the host app and FSKit extension.
/// Stored in the shared Keychain access group so that probeResource and loadResource
/// reliably receive the desired volume name and read-only flags without depending
/// on macOS /sbin/mount option passthrough quirks.
public struct MountContext: Codable, Equatable, Sendable {
    public let volumeName: String
    public let isReadOnly: Bool
    public let mountPoint: String
    public let createdAt: Date

    public init(volumeName: String, isReadOnly: Bool, mountPoint: String, createdAt: Date = Date()) {
        self.volumeName = volumeName
        self.isReadOnly = isReadOnly
        self.mountPoint = mountPoint
        self.createdAt = createdAt
    }

    /// Default TTL for a mount attempt before it is considered stale (2 minutes).
    public static let defaultTTL: TimeInterval = 120.0

    public var isExpired: Bool {
        Date().timeIntervalSince(createdAt) > Self.defaultTTL
    }
}

public enum MountContextStore {
    private static let accountPrefix = "mountctx:"

    public static func accountKey(for cipherPath: String) -> String {
        accountPrefix + Vault.canonicalKey(path: cipherPath)
    }

    /// Saves the mount context into the shared Keychain.
    @discardableResult
    public static func save(_ context: MountContext, for cipherPath: String) -> Bool {
        guard let data = try? JSONEncoder().encode(context) else {
            logger.error("Failed to encode MountContext for \(cipherPath, privacy: .private)")
            return false
        }
        let account = accountKey(for: cipherPath)
        let ok = KeychainStore.saveCredential(account: account, data: data)
        if ok {
            logger.info("Saved MountContext '\(context.volumeName, privacy: .public)' (readOnly: \(context.isReadOnly)) for \(cipherPath, privacy: .private)")
        }
        return ok
    }

    /// Loads the active mount context for a given ciphertext directory.
    /// Returns nil if not found or expired.
    public static func load(for cipherPath: String) -> MountContext? {
        let account = accountKey(for: cipherPath)
        guard let data = KeychainStore.loadCredential(account: account) else {
            return nil
        }
        guard let context = try? JSONDecoder().decode(MountContext.self, from: data) else {
            logger.error("Failed to decode MountContext for \(cipherPath, privacy: .private)")
            return nil
        }
        if context.isExpired {
            logger.info("MountContext for \(cipherPath, privacy: .private) has expired; removing")
            delete(for: cipherPath)
            return nil
        }
        return context
    }

    /// Removes the mount context.
    @discardableResult
    public static func delete(for cipherPath: String) -> Bool {
        let account = accountKey(for: cipherPath)
        return KeychainStore.deleteCredential(account: account)
    }
}
