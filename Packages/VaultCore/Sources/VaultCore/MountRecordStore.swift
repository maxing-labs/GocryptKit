import Foundation

/// Persists the mapping between active mount points and their corresponding ciphertext directories.
///
/// Because CLI invocations of `mount` and `umount` run in distinct processes,
/// the relationship between a mount point and its canonical ciphertext directory
/// must outlive the process that mounted it, allowing `umount` to correctly purge
/// the ephemeral Keychain credential upon unmount.
public enum MountRecordStore {
    private static let keyPrefix = "mountedVault:"
    private static let liveKeyPrefix = "mountedVaultAt:"

    /// Keyed by `Vault.canonicalKey` (realpath), like the rest of the app, so any
    /// spelling of the mount point (symlink, /tmp alias, letter case) finds it.
    public static func mountRecordKey(for mountPoint: URL) -> String {
        keyPrefix + Vault.canonicalKey(path: mountPoint.path)
    }

    /// Keyed by the mount point as the mount table lists it (`f_mntonname`), taken
    /// as is. The mount table poll runs on the main thread, and resolving a mount
    /// point is answered by the volume's extension: it hangs while FSKit is stuck.
    static func liveRecordKey(mountOnName: String) -> String {
        liveKeyPrefix + mountOnName
    }

    /// Records the ciphertext directory canonical key associated with a mount point.
    /// `mountOnName` is the mount table's name for the mount, once it is mounted.
    public static func rememberCipherDir(_ cipherDir: URL, for mountPoint: URL, mountOnName: String? = nil,
                                         userDefaults: UserDefaults = .standard) {
        let cipherKey = Vault.canonicalKey(path: cipherDir.path)
        userDefaults.set(cipherKey, forKey: mountRecordKey(for: mountPoint))
        if let mountOnName {
            userDefaults.set(cipherKey, forKey: liveRecordKey(mountOnName: mountOnName))
        }
    }

    /// Retrieves and removes the recorded ciphertext directory canonical key for a mount point.
    /// Call it once the volume is unmounted, with the mount table's name it had.
    public static func forgetCipherDir(for mountPoint: URL, mountOnName: String? = nil,
                                       userDefaults: UserDefaults = .standard) -> String? {
        if let mountOnName {
            userDefaults.removeObject(forKey: liveRecordKey(mountOnName: mountOnName))
        }
        let key = mountRecordKey(for: mountPoint)
        let path = userDefaults.string(forKey: key)
        userDefaults.removeObject(forKey: key)
        return path
    }

    /// The recorded ciphertext directory of a live mount, by its mount table name.
    /// Touches no file system.
    public static func cipherDir(forMountOnName mountOnName: String, userDefaults: UserDefaults = .standard) -> String? {
        userDefaults.string(forKey: liveRecordKey(mountOnName: mountOnName))
    }

    /// Looks up the recorded ciphertext directory canonical key without removing it.
    public static func cipherDir(for mountPoint: URL, userDefaults: UserDefaults = .standard) -> String? {
        userDefaults.string(forKey: mountRecordKey(for: mountPoint))
    }
}
