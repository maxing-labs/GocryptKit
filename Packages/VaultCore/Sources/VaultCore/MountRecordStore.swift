import Foundation

/// Persists the mapping between active mount points and their corresponding ciphertext directories.
///
/// Because CLI invocations of `mount` and `umount` run in distinct processes,
/// the relationship between a mount point and its canonical ciphertext directory
/// must outlive the process that mounted it, allowing `umount` to correctly purge
/// the ephemeral Keychain credential upon unmount.
public enum MountRecordStore {
    private static let keyPrefix = "mountedVault:"

    public static func mountRecordKey(for mountPoint: URL) -> String {
        keyPrefix + mountPoint.resolvingSymlinksInPath().path
    }

    /// Records the ciphertext directory canonical key associated with a mount point.
    public static func rememberCipherDir(_ cipherDir: URL, for mountPoint: URL, userDefaults: UserDefaults = .standard) {
        userDefaults.set(Vault.canonicalKey(path: cipherDir.path), forKey: mountRecordKey(for: mountPoint))
    }

    /// Retrieves and removes the recorded ciphertext directory canonical key for a mount point.
    public static func forgetCipherDir(for mountPoint: URL, userDefaults: UserDefaults = .standard) -> String? {
        let key = mountRecordKey(for: mountPoint)
        let path = userDefaults.string(forKey: key)
        userDefaults.removeObject(forKey: key)
        return path
    }

    /// Looks up the recorded ciphertext directory canonical key without removing it.
    public static func cipherDir(for mountPoint: URL, userDefaults: UserDefaults = .standard) -> String? {
        userDefaults.string(forKey: mountRecordKey(for: mountPoint))
    }
}
