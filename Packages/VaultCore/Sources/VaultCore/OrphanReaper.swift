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
}
