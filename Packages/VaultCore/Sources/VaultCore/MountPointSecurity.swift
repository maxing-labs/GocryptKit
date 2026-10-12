import Foundation

/// Keeps mounted plaintext out of reach of other local accounts.
///
/// FSKit volumes are mounted with `noowners`: every file appears to be owned by
/// whoever looks at it, so the permission bits inside the volume keep nobody
/// out. What does is the path leading to the mount point. The home directory is
/// typically 0750 with every account in group `staff`, so a 0755 `~/Volumes`
/// leaves mounted vaults one `cd` away from the other users of the Mac.
public enum MountPointSecurity {
    #if os(macOS)
    /// `~/Volumes`, the parent of every default mount point (see `Vault.makeDefault`).
    public static var defaultMountRoot: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Volumes")
    }
    #endif

    /// Creates `directory` with mode 0700, or tightens it to 0700 when the current
    /// user owns it and group or others have any access. A directory owned by
    /// someone else is left alone. Returns whether anything was created or changed.
    @discardableResult
    public static func makePrivate(_ directory: URL) throws -> Bool {
        var info = stat()
        if lstat(directory.path, &info) != 0 {
            guard errno == ENOENT else { throw POSIXError(POSIXError.Code(rawValue: errno) ?? .EIO) }
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            return true
        }
        guard (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == getuid(), (info.st_mode & 0o077) != 0 else {
            return false
        }
        guard chmod(directory.path, 0o700) == 0 else {
            throw POSIXError(POSIXError.Code(rawValue: errno) ?? .EIO)
        }
        return true
    }

    /// Whether accounts other than the owner can walk the whole path down to
    /// `directory`: every component up to `/` is searchable by group or others.
    /// ACLs are not considered. A missing component counts as not reachable.
    public static func isReachableByOthers(_ directory: URL) -> Bool {
        var current = directory.standardizedFileURL
        while true {
            var info = stat()
            guard stat(current.path, &info) == 0, (info.st_mode & 0o011) != 0 else {
                return false
            }
            if current.path == "/" {
                return true
            }
            current = current.deletingLastPathComponent()
        }
    }
}
