import Foundation
import libgocryptfs

public final class GocryptfsEngine: VaultEngine, @unchecked Sendable {
    public let volumeID: Int32
    private let lock = NSLock()
    private var isShutdown = false

    /// Opens the vault without asking for its scrypt hash back (the extension's case):
    /// no copy of the hash is made on either side of the C boundary.
    public convenience init(cipherDir: URL, credential: VaultCredential) throws {
        try self.init(cipherDir: cipherDir, credential: credential, hashOut: nil)
    }

    /// Opens the vault and hands back its scrypt hash, which can open it again
    /// without the password (the host stores it for the extension).
    public convenience init(cipherDir: URL, credential: VaultCredential, returnedScryptHash: inout Data?) throws {
        let hash = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: 32)
        hash.initialize(repeating: 0)
        defer {
            memset_s(hash.baseAddress, hash.count, 0, hash.count)
            hash.deallocate()
        }
        try self.init(cipherDir: cipherDir, credential: credential, hashOut: hash)
        returnedScryptHash = Data(hash)
    }

    private init(cipherDir: URL, credential: VaultCredential, hashOut: UnsafeMutableBufferPointer<UInt8>?) throws {
        var volID: Int32 = -1

        let dirCStr = strdup(cipherDir.path)
        defer { free(dirCStr) }

        switch credential {
        case .password(let pwd):
            let pwdCStr = strdup(pwd)
            defer {
                if let p = pwdCStr {
                    memset_s(p, strlen(p), 0, strlen(p))
                    free(p)
                }
            }
            volID = gcfc_init(dirCStr, pwdCStr, nil, 0, hashOut?.baseAddress, hashOut?.count ?? 0)
        case .scryptHash(let hash):
            // Borrowed, not copied: the caller owns (and may wipe) the hash.
            hash.withUnsafeBytes { buf in
                guard let base = buf.baseAddress else { return }
                volID = gcfc_init(dirCStr, nil, UnsafeMutablePointer(mutating: base.assumingMemoryBound(to: UInt8.self)),
                                  buf.count, hashOut?.baseAddress, hashOut?.count ?? 0)
            }
        }

        if volID == -1 {
            throw VaultError.configNotFound
        } else if volID == -2 {
            throw VaultError.authFailed
        } else if volID == -3 {
            // Engine internal panic caught by recover() at C ABI boundary.
            // Not a user-correctable condition, but prevents host extension process from crashing.
            throw VaultError.initFailed(volID)
        } else if volID < 0 {
            throw VaultError.invalidCipherDir
        }

        self.volumeID = volID
    }

    deinit {
        shutdown()
    }

    public func shutdown() {
        lock.lock()
        defer { lock.unlock() }
        guard !isShutdown else { return }
        isShutdown = true
        gcfc_close(volumeID)
    }

    /// Returns a C result that is >= 0, or throws the negative errno it carries.
    /// Every gcfc_* call that can fail goes through here (VaultXattr too). A
    /// shut-down engine needs no check of its own: its volume ID is never
    /// reused, so the engine answers EBADF.
    @discardableResult
    static func check<T: SignedInteger>(_ result: T) throws -> T {
        if result < 0 { throw VaultError.posix(Int32(-result)) }
        return result
    }

    public func list(_ plainDir: String) throws -> [DirEntry] {
        let dirCStr = strdup(plainDir)
        defer { free(dirCStr) }

        var entriesPtr: UnsafeMutablePointer<gcfc_dir_entry_t>? = nil
        var count: Int32 = 0

        try Self.check(gcfc_list_dir(volumeID, dirCStr, &entriesPtr, &count))

        guard let entries = entriesPtr, count > 0 else {
            return []
        }

        defer {
            gcfc_free_dir_entries(entries, count)
        }

        var result: [DirEntry] = []
        result.reserveCapacity(Int(count))

        for i in 0..<Int(count) {
            let entry = entries[i]
            if let namePtr = entry.name {
                let name = String(cString: namePtr)
                result.append(DirEntry(name: name, mode: entry.mode))
            }
        }
        return result
    }

    /// The ciphertext path of `plain`, or nil when it cannot be resolved.
    public func cipherPath(_ plain: String) -> String? {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }

        var cPathPtr: UnsafeMutablePointer<CChar>?
        guard gcfc_cipher_path(volumeID, plainCStr, &cPathPtr) == 0, let cPathPtr else {
            return nil
        }
        defer { gcfc_free_string(cPathPtr) }
        return String(cString: cPathPtr)
    }

    public func plainSize(cipherSize: UInt64) -> UInt64 {
        gcfc_plain_size(volumeID, cipherSize)
    }

    public func readlink(_ plain: String) throws -> String {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }

        var targetPtr: UnsafeMutablePointer<CChar>?
        try Self.check(gcfc_readlink(volumeID, plainCStr, &targetPtr))
        guard let targetPtr else { throw VaultError.posix(EIO) }
        defer { gcfc_free_string(targetPtr) }
        return String(cString: targetPtr)
    }

    public func open(_ plain: String) throws -> Int32 {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }
        return try Self.check(gcfc_open_read_mode(volumeID, plainCStr))
    }

    public func openWrite(_ plain: String, mode: UInt32 = 0o644) throws -> Int32 {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }
        return try Self.check(gcfc_open_write_mode(volumeID, plainCStr, mode))
    }

    /// Exclusively creates a new file (O_CREAT|O_EXCL) and returns a writable handle.
    /// Throws `.posix(EEXIST)` when the name already exists.
    public func createFile(_ plain: String, mode: UInt32 = 0o644) throws -> Int32 {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }
        return try Self.check(gcfc_create_file(volumeID, plainCStr, mode))
    }

    /// Opens an existing file for writing. Never creates: a writer that lost its
    /// handle must not resurrect a deleted file or land in whatever replaced it.
    public func openWriteExisting(_ plain: String) throws -> Int32 {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }
        return try Self.check(gcfc_open_write_existing(volumeID, plainCStr))
    }

    /// Attributes of the item at `plain`, resolved through directory fds without
    /// following symlinks. Throws `.posix(ENOENT)` when the item does not exist.
    public func stat(_ plain: String) throws -> ItemStat {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }
        var st = gcfc_stat_t()
        try Self.check(gcfc_lstat(volumeID, plainCStr, &st))
        return ItemStat(st)
    }

    /// Attributes of an open handle. Keeps working after the file was unlinked or replaced.
    public func stat(handle: Int32) throws -> ItemStat {
        var st = gcfc_stat_t()
        try Self.check(gcfc_fstat(volumeID, handle, &st))
        return ItemStat(st)
    }

    public func stat(_ item: ItemRef) throws -> ItemStat {
        switch item {
        case .path(let plain): return try stat(plain)
        case .handle(let handle): return try stat(handle: handle)
        }
    }

    /// Calls `body` with the C arguments for `item`: a path, or a handle (>= 0).
    func withCItem<T>(_ item: ItemRef, _ body: (UnsafeMutablePointer<CChar>?, Int32) throws -> T) rethrows -> T {
        switch item {
        case .path(let plain):
            let plainCStr = strdup(plain)
            defer { free(plainCStr) }
            return try body(plainCStr, -1)
        case .handle(let handle):
            return try body(nil, handle)
        }
    }

    public func read(_ h: Int32, offset: UInt64, into buffer: UnsafeMutableRawBufferPointer) throws -> Int {
        try read(h, offset: offset, into: buffer, length: buffer.count)
    }

    public func read(_ h: Int32, offset: UInt64, into buffer: UnsafeMutableRawBufferPointer, length: Int) throws -> Int {
        guard let baseAddress = buffer.baseAddress else { return 0 }
        let toRead = min(length, buffer.count)
        guard toRead > 0 else { return 0 }
        return Int(try Self.check(gcfc_read_file(volumeID, h, offset, baseAddress, toRead)))
    }

    public func write(_ h: Int32, offset: UInt64, from buffer: UnsafeRawBufferPointer) throws -> Int {
        guard let baseAddress = buffer.baseAddress else { return 0 }
        let mutable = UnsafeMutableRawPointer(mutating: baseAddress)
        return Int(try Self.check(gcfc_write_file(volumeID, h, offset, mutable, buffer.count)))
    }

    public func truncate(_ plain: String, size: UInt64) throws {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }
        try Self.check(gcfc_truncate(volumeID, plainCStr, size))
    }

    /// Truncate the acquired writable handle, preserving inode identity across renames.
    public func truncate(_ handle: Int32, size: UInt64) throws {
        try Self.check(gcfc_ftruncate(volumeID, handle, size))
    }

    public func remove(_ plain: String) throws {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }
        try Self.check(gcfc_remove_file(volumeID, plainCStr))
    }

    public func mkdir(_ plain: String, mode: UInt32 = 0o755) throws {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }
        try Self.check(gcfc_mkdir(volumeID, plainCStr, mode))
    }

    public func rmdir(_ plain: String) throws {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }
        try Self.check(gcfc_rmdir(volumeID, plainCStr))
    }

    /// Changes the permission bits of the item itself; never follows a symlink.
    public func chmod(_ plain: String, mode: UInt32) throws {
        var changes = AttributeChanges()
        changes.mode = mode
        try setAttributes(.path(plain), changes)
    }

    /// Applies `changes` to the item itself (never following a symlink), or
    /// through an open handle.
    public func setAttributes(_ item: ItemRef, _ changes: AttributeChanges) throws {
        var req = changes.request
        switch item {
        case .path(let plain):
            let plainCStr = strdup(plain)
            defer { free(plainCStr) }
            try Self.check(gcfc_setattr(volumeID, plainCStr, &req))
        case .handle(let handle):
            try Self.check(gcfc_fsetattr(volumeID, handle, &req))
        }
    }

    public func rename(from oldPath: String, to newPath: String) throws {
        let oldCStr = strdup(oldPath)
        defer { free(oldCStr) }
        let newCStr = strdup(newPath)
        defer { free(newCStr) }
        try Self.check(gcfc_rename(volumeID, oldCStr, newCStr))
    }

    public func close(_ h: Int32) {
        gcfc_close_file(volumeID, h)
    }
}

/// An item addressed by its plaintext path, or by an open handle. A handle keeps
/// working after the file was unlinked or replaced and its path names something else.
public enum ItemRef: Sendable {
    case path(String)
    case handle(Int32)
}

/// Attribute changes for `setAttributes`. Fields left `nil` stay as they are.
/// On a `noowners` mount the kernel never forwards `uid`/`gid` changes.
public struct AttributeChanges: Sendable {
    public var mode: UInt32?
    public var uid: UInt32?
    public var gid: UInt32?
    /// Only the user-visible flags (hidden, immutable, append, nodump, opaque,
    /// archived) are applied; the ciphertext file keeps its other flags.
    public var flags: UInt32?
    public var accessTime: timespec?
    public var modifyTime: timespec?
    public var birthTime: timespec?

    public init() {}

    public var isEmpty: Bool {
        mode == nil && uid == nil && gid == nil && flags == nil
            && accessTime == nil && modifyTime == nil && birthTime == nil
    }

    var request: gcfc_setattr_t {
        var req = gcfc_setattr_t()
        func set(_ bit: Int32) { req.valid |= UInt32(bit) }
        if let mode { req.mode = mode; set(GCFC_SET_MODE) }
        if let uid { req.uid = uid; set(GCFC_SET_UID) }
        if let gid { req.gid = gid; set(GCFC_SET_GID) }
        if let flags { req.flags = flags; set(GCFC_SET_FLAGS) }
        if let t = accessTime { (req.atime_sec, req.atime_nsec) = (Int64(t.tv_sec), Int64(t.tv_nsec)); set(GCFC_SET_ATIME) }
        if let t = modifyTime { (req.mtime_sec, req.mtime_nsec) = (Int64(t.tv_sec), Int64(t.tv_nsec)); set(GCFC_SET_MTIME) }
        if let t = birthTime { (req.btime_sec, req.btime_nsec) = (Int64(t.tv_sec), Int64(t.tv_nsec)); set(GCFC_SET_BTIME) }
        return req
    }
}

/// Attributes of one vault item. `size` is the plaintext size for regular files and symlinks.
public struct ItemStat: Sendable {
    public let inode: UInt64
    public let size: UInt64
    /// Full `st_mode`, including the file type bits.
    public let mode: UInt32
    public let linkCount: UInt32
    public let uid: UInt32
    public let gid: UInt32
    public let flags: UInt32
    public let accessTime: timespec
    public let modifyTime: timespec
    public let changeTime: timespec
    public let birthTime: timespec

    init(_ st: gcfc_stat_t) {
        inode = st.ino
        size = st.size
        mode = st.mode
        linkCount = st.nlink
        uid = st.uid
        gid = st.gid
        flags = st.flags
        accessTime = timespec(tv_sec: Int(st.atime_sec), tv_nsec: Int(st.atime_nsec))
        modifyTime = timespec(tv_sec: Int(st.mtime_sec), tv_nsec: Int(st.mtime_nsec))
        changeTime = timespec(tv_sec: Int(st.ctime_sec), tv_nsec: Int(st.ctime_nsec))
        birthTime = timespec(tv_sec: Int(st.btime_sec), tv_nsec: Int(st.btime_nsec))
    }

    public var isDirectory: Bool { (mode & UInt32(S_IFMT)) == UInt32(S_IFDIR) }
    public var isSymlink: Bool { (mode & UInt32(S_IFMT)) == UInt32(S_IFLNK) }
}
