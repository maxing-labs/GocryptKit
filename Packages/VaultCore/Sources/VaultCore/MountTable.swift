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

        public init(fileSystemType: String, source: String, mountPoint: String) {
            self.fileSystemType = fileSystemType
            self.source = source
            self.mountPoint = mountPoint
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
            Entry(fileSystemType: string(from: fs.f_fstypename),
                  source: string(from: fs.f_mntfromname),
                  mountPoint: string(from: fs.f_mntonname))
        }
    }

    /// Currently mounted gocryptfs volumes, keyed by the ciphertext directory's `Vault.canonicalKey`.
    public static func gocryptfsMounts() -> [String: Entry] {
        var result: [String: Entry] = [:]
        for entry in entries() where entry.fileSystemType == gocryptfsTypeName {
            result[Vault.canonicalKey(path: entry.sourcePath)] = entry
        }
        return result
    }

    /// Rebinds fixed-size C char tuple arrays from `statfs` to a Swift String.
    private static func string<T>(from tuple: T) -> String {
        withUnsafePointer(to: tuple) { ptr in
            ptr.withMemoryRebound(to: CChar.self,
                                  capacity: MemoryLayout<T>.size) { String(cString: $0) }
        }
    }
}
