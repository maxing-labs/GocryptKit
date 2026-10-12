import Foundation

/// Read-only snapshot of the kernel mount table.
///
/// UI mount status is always derived live from here rather than locally cached app state.
/// As documented in `Vault`: volumes mounted via CLI, unmounted in Finder, or persisting across
/// app restarts would otherwise cause cached state to desynchronize.
/// Calling `getfsstat(2)` is a fast system call that can be polled frequently with negligible overhead.
public enum MountTable {
    /// File system type name declared in FSKit's `volumeStatistics`, matching the
    /// `-t` argument passed to `/sbin/mount -t gocryptfs`.
    public static let gocryptfsTypeName = "gocryptfs"

    public struct Entry: Sendable, Hashable {
        /// `f_fstypename`, e.g. "gocryptfs", "apfs", "exfat".
        public let fileSystemType: String
        /// Raw `f_mntfromname`. FSKit stores a file URL here (e.g. `file:///tmp/vault/`)
        /// rather than a bare path. Use `sourcePath` for the resolved POSIX path.
        public let source: String
        /// `f_mntonname`, target mount point.
        public let mountPoint: String
        /// Whether the mount is read-only (MNT_RDONLY flag set in kernel statfs).
        public let isReadOnly: Bool
        /// `f_owner`, the user who mounted the volume.
        public let ownerUID: uid_t

        public init(fileSystemType: String, source: String, mountPoint: String, isReadOnly: Bool = false,
                    ownerUID: uid_t = getuid()) {
            self.fileSystemType = fileSystemType
            self.source = source
            self.mountPoint = mountPoint
            self.isReadOnly = isReadOnly
            self.ownerUID = ownerUID
        }

        /// Decodes `source` into a local path. FSKit writes ciphertext directories as percent-encoded
        /// `file://` URLs with trailing slashes; this resolves them back for path comparison.
        public var sourcePath: String { MountTable.decodeSource(source) }
    }

    /// Decodes `f_mntfromname` into a local POSIX path. Returns raw string if not a file URL
    /// (e.g. device nodes like `/dev/disk3s1` for standard filesystems).
    static func decodeSource(_ raw: String) -> String {
        guard raw.hasPrefix("file://") else { return raw }
        if let url = URL(string: raw), url.isFileURL {
            return url.standardizedFileURL.path
        }
        // Fallback if URL parsing fails (e.g. unescaped characters): strip scheme,
        // decode percent encoding, and remove trailing slash.
        let stripped = String(raw.dropFirst("file://".count))
        let decoded = stripped.removingPercentEncoding ?? stripped
        if decoded.count > 1 && decoded.hasSuffix("/") { return String(decoded.dropLast()) }
        return decoded
    }

    /// Returns all current system mount points. Fails safe by returning empty array:
    /// displaying volumes as unmounted is a safe degradation — mounting an already-mounted
    /// volume will simply produce an "already mounted" error. Conversely, falsely reporting
    /// a volume as mounted could mislead users into believing plaintext data is accessible.
    ///
    /// Note: `statfs` is both a struct name and a function in Darwin headers.
    /// Writing `[statfs]` would be parsed as an array of functions, so we alias the struct type.
    private typealias StatFS = statfs

    public static func entries() -> [Entry] {
        var count = getfsstat(nil, 0, MNT_NOWAIT)
        guard count > 0 else { return [] }
        // Add headroom in case new volumes are mounted between getfsstat calls
        count += 8
        var buffer = [StatFS](repeating: StatFS(), count: Int(count))
        let byteCount = Int32(MemoryLayout<StatFS>.stride * Int(count))
        let actual = buffer.withUnsafeMutableBufferPointer { ptr -> Int32 in
            getfsstat(ptr.baseAddress, byteCount, MNT_NOWAIT)
        }
        guard actual > 0 else { return [] }

        return buffer.prefix(Int(actual)).map { fs in
            let mountPoint = string(from: fs.f_mntonname)
            let isRO = ((fs.f_flags & UInt32(MNT_RDONLY)) != 0) || mountPoint.hasSuffix(Vault.readOnlySuffix)
            return Entry(fileSystemType: string(from: fs.f_fstypename),
                         source: string(from: fs.f_mntfromname),
                         mountPoint: mountPoint,
                         isReadOnly: isRO,
                         ownerUID: fs.f_owner)
        }
    }

    /// Currently mounted gocryptfs volumes, keyed by the ciphertext directory's `Vault.canonicalKey`.
    public static func gocryptfsMounts() -> [String: Entry] {
        gocryptfsMounts(in: entries(), ownedBy: nil)
    }

    /// gocryptfs volumes mounted by `uid` only. Anything that unmounts on the user's
    /// behalf must use this: other accounts' volumes are not ours to take down.
    public static func gocryptfsMounts(ownedBy uid: uid_t) -> [String: Entry] {
        gocryptfsMounts(in: entries(), ownedBy: uid)
    }

    static func gocryptfsMounts(in entries: [Entry], ownedBy uid: uid_t?) -> [String: Entry] {
        var result: [String: Entry] = [:]
        for entry in entries where entry.fileSystemType == gocryptfsTypeName {
            if let uid, entry.ownerUID != uid { continue }
            result[cipherDirKey(of: entry)] = entry
        }
        return result
    }

    /// The ciphertext directory of a gocryptfs mount. FSKit writes "unknown" instead
    /// of the file URL when that does not fit f_mntfromname (a long non-ASCII path);
    /// the record the host keeps per mount point names the directory then. Without
    /// one, the mount point keeps such volumes apart.
    static func cipherDirKey(of entry: Entry) -> String {
        if entry.source.hasPrefix("file://") {
            return Vault.canonicalKey(path: entry.sourcePath)
        }
        return MountRecordStore.cipherDir(forMountOnName: entry.mountPoint) ?? entry.mountPoint
    }

    /// Mount point of the gocryptfs volume that holds `path`, if any. A vault inside
    /// a mounted vault must not be mounted: the mount waits for its extension, which
    /// waits to read the vault through the outer volume, and meanwhile statfs of every
    /// FSKit volume (external disks too) hangs.
    public static func gocryptfsVolume(containing path: String) -> String? {
        var fs = StatFS()
        guard statfs(path, &fs) == 0, string(from: fs.f_fstypename) == gocryptfsTypeName else { return nil }
        return string(from: fs.f_mntonname)
    }

    /// Mount point of the gocryptfs volume a vault would be read through, if any:
    /// the one holding its directory, or the one its gocryptfs.conf lies in. The
    /// extension reads the conf following symlinks, so a conf linked into a
    /// mounted vault deadlocks FSKit the same way.
    public static func gocryptfsVolume(holdingVaultAt cipherDir: String,
                                       volumeOf: (String) -> String? = gocryptfsVolume(containing:)) -> String? {
        volumeOf(cipherDir) ?? volumeOf((cipherDir as NSString).appendingPathComponent("gocryptfs.conf"))
    }

    /// Rebinds fixed-size C char tuple arrays from `statfs` to a Swift String,
    /// explicitly bounded by the tuple's memory size to prevent buffer over-read.
    private static func string<T>(from tuple: T) -> String {
        withUnsafePointer(to: tuple) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<T>.size) { cStrPtr in
                let maxLen = MemoryLayout<T>.size
                let count = (0..<maxLen).first(where: { cStrPtr[$0] == 0 }) ?? maxLen
                return String(data: Data(bytes: cStrPtr, count: count), encoding: .utf8) ?? ""
            }
        }
    }
}
