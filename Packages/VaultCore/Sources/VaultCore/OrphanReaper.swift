import Foundation

/// Pure logic for calculating orphaned Keychain credentials that need to be reaped.
/// Kept strictly side-effect free so it can be thoroughly unit tested without system dependencies.
public enum OrphanReaper {

    /// Computes the list of Keychain account keys that belong to known vaults
    /// but are NOT present in the currently active mounts.
    ///
    /// - Parameters:
    ///   - knownVaultPaths: Cipher directory paths of all registered or known vaults.
    ///   - mountedCanonicalKeys: Set of canonical keys of all currently mounted filesystems.
    ///   - includeMountContext: Whether to also include ephemeral mountctx keys for reaping.
    /// - Returns: Ordered list of unique canonical keys that should be deleted from the Keychain.
    public static func accountsToReap(
        knownVaultPaths: [String],
        mountedCanonicalKeys: Set<String>,
        includeMountContext: Bool = false
    ) -> [String] {
        var reaped = Set<String>()
        var result = [String]()

        for path in knownVaultPaths {
            let canonical = Vault.canonicalKey(path: path)
            if !mountedCanonicalKeys.contains(canonical) && !reaped.contains(canonical) {
                reaped.insert(canonical)
                result.append(canonical)
                if includeMountContext {
                    let mountCtxKey = MountContextStore.accountKey(for: path)
                    if !reaped.contains(mountCtxKey) {
                        reaped.insert(mountCtxKey)
                        result.append(mountCtxKey)
                    }
                }
            }
        }

        return result
    }

    /// How long a stored item is left alone. A mount attempt holds its credential
    /// for at most three tries of 15 s plus the retry delays; anything younger may
    /// belong to a mount that another process (the CLI, a second window) is running.
    public static let gracePeriod: TimeInterval = 120

    /// Accounts to delete, computed from what is actually stored rather than from
    /// the registered vaults: a credential left behind by an interrupted CLI mount
    /// of an unregistered vault is an orphan too.
    ///
    /// - Parameters:
    ///   - stored: Every item of the service, with the time it was saved.
    ///   - protectedVaultKeys: Canonical keys of vaults that are mounted or being
    ///     mounted by this process.
    ///   - now: Reference time; an item without a date counts as old.
    public static func accountsToReap(
        stored: [KeychainStore.StoredItem],
        protectedVaultKeys: Set<String>,
        now: Date = Date(),
        gracePeriod: TimeInterval = OrphanReaper.gracePeriod
    ) -> [String] {
        var result = [String]()
        for item in stored where !result.contains(item.account) {
            if protectedVaultKeys.contains(MountContextStore.vaultKey(forAccount: item.account)) {
                continue
            }
            if let savedAt = item.savedAt, now.timeIntervalSince(savedAt) < gracePeriod {
                continue
            }
            result.append(item.account)
        }
        return result
    }
}
