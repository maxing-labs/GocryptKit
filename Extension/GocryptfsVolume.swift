import Foundation
import ExtensionFoundation
import FSKit
import OSLog
import VaultCore

private let logger = Logger(subsystem: "com.xwei.GocryptKit.AppEx", category: "GocryptfsVolume")

final class GocryptfsVolume: FSVolume,
                             FSVolume.Operations,
                             FSVolume.OpenCloseOperations,
                             FSVolume.ReadWriteOperations,
                             FSVolume.RenameOperations,
                             FSVolume.PreallocateOperations,
                             FSVolume.PathConfOperations,
                             @unchecked Sendable {

    let engine: GocryptfsEngine
    let cipherURL: URL
    let rootItem: GocryptfsItem
    let isReadOnly: Bool

    let cacheLock = NSLock()
    var pathCache: [String: GocryptfsItem] = [:]
    /// Key of a name in directory listings. Tests replace it to force collisions.
    var listingKey: (String) -> UInt64 = GocryptfsVolume.listingKey(for:)

    init(engine: GocryptfsEngine, cipherURL: URL, volumeName: String? = nil, isReadOnly: Bool = false) throws {
        self.engine = engine
        self.cipherURL = cipherURL
        self.isReadOnly = isReadOnly

        var rootStat = stat()
        if lstat(cipherURL.path, &rootStat) != 0 {
            throw POSIXError(POSIXError.Code(rawValue: errno) ?? .ENOENT)
        }

        let root = GocryptfsItem(
            id: .rootDirectory,
            plainPath: "",
            name: ".",
            itemType: .directory,
            inode: rootStat.st_ino,
            parent: nil
        )
        self.rootItem = root
        self.pathCache[""] = root

        let nameString: String
        if let custom = volumeName, !custom.isEmpty {
            nameString = custom
        } else {
            let baseName = cipherURL.lastPathComponent
            nameString = isReadOnly ? "\(baseName)\(Vault.readOnlySuffix)" : baseName
        }
        let volName = FSFileName(string: nameString)
        super.init(volumeID: FSVolume.Identifier(uuid: UUID()), volumeName: volName)
        self.name = volName
        logger.info("Initialized GocryptfsVolume '\(nameString, privacy: .private)' for \(cipherURL.path, privacy: .private) (readOnly: \(isReadOnly))")
    }

    @available(macOS 26.4, *)
    public var requestedMountOptions: FSVolume.MountOptions {
        isReadOnly ? .readOnly : []
    }

    // MARK: - FSVolume.Operations

    public var volumeStatistics: FSStatFSResult {
        var statfsResult = statfs()
        let res = FSStatFSResult(fileSystemTypeName: "gocryptfs")
        if statfs(cipherURL.path, &statfsResult) == -1 {
            return res
        }
        res.blockSize = Int(statfsResult.f_bsize)
        res.ioSize = Int(statfsResult.f_iosize)
        res.totalBlocks = UInt64(statfsResult.f_blocks)
        res.availableBlocks = UInt64(statfsResult.f_bavail)
        res.freeBlocks = UInt64(statfsResult.f_bfree)
        res.usedBlocks = res.totalBlocks > res.freeBlocks ? (res.totalBlocks - res.freeBlocks) : 0
        res.totalFiles = UInt64(statfsResult.f_files)
        res.freeFiles = UInt64(statfsResult.f_ffree)
        res.fileSystemSubType = Int(statfsResult.f_fssubtype)
        return res
    }

    public var supportedVolumeCapabilities: FSVolume.SupportedCapabilities {
        let cap = FSVolume.SupportedCapabilities()
        cap.supportsSymbolicLinks = true
        cap.supportsHardLinks = false
        cap.supportsHiddenFiles = true
        cap.supportsPersistentObjectIDs = false
        cap.supports64BitObjectIDs = true
        cap.doesNotSupportSettingFilePermissions = true
        cap.caseFormat = .sensitive
        return cap
    }

    public func activate(options: FSTaskOptions, replyHandler: @escaping (FSItem?, Error?) -> Void) {
        replyHandler(rootItem, nil)
    }

    public func deactivate(options: FSDeactivateOptions = [], replyHandler: @escaping (Error?) -> Void) {
        cacheLock.lock()
        for item in pathCache.values {
            item.forceClose(using: engine)
        }
        cacheLock.unlock()
        replyHandler(nil)
    }

    public func mount(options: FSTaskOptions, replyHandler: @escaping (Error?) -> Void) {
        replyHandler(nil)
    }

    public func unmount(replyHandler: @escaping () -> Void) {
        cacheLock.lock()
        for item in pathCache.values {
            item.forceClose(using: engine)
        }
        pathCache.removeAll()
        cacheLock.unlock()
        engine.shutdown()
        replyHandler()
    }

    public func synchronize(flags: FSSyncFlags, replyHandler: @escaping (Error?) -> Void) {
        // Nothing is buffered here: every write() is encrypted and handed to the
        // backing file system with pwrite(2) before its reply. Durability beyond
        // that is the backing file system's; no fsync is issued on its files.
        replyHandler(nil)
    }

    public func setVolumeName(_ name: FSFileName, replyHandler: @escaping (FSFileName?, Error?) -> Void) {
        guard !isReadOnly else {
            return replyHandler(nil, POSIXError(.EROFS))
        }
        self.name = name
        logger.info("Updated volumeName to '\(name.string ?? "", privacy: .private)'")
        replyHandler(name, nil)
    }

    public func reclaimItem(_ item: FSItem, replyHandler: @escaping (Error?) -> Void) {
        guard let gcItem = item as? GocryptfsItem else {
            return replyHandler(POSIXError(.EINVAL))
        }

        // Only drop the cache entry if it still points at this very item. After
        // a remove or replace its path may belong to a newer item that must stay
        // cached.
        cacheLock.lock()
        if pathCache[gcItem.plainPath] === gcItem {
            pathCache.removeValue(forKey: gcItem.plainPath)
        }
        cacheLock.unlock()

        gcItem.forceClose(using: engine)
        replyHandler(nil)
    }

    public func lookupItem(named name: FSFileName,
                           inDirectory directory: FSItem,
                           replyHandler: @escaping (FSItem?, FSFileName?, Error?) -> Void) {
        guard let dirItem = directory as? GocryptfsItem, let nameString = name.string else {
            return replyHandler(nil, nil, POSIXError(.EINVAL))
        }

        if nameString == "." {
            return replyHandler(dirItem, name, nil)
        }
        if nameString == ".." {
            return replyHandler(dirItem.parent ?? rootItem, name, nil)
        }

        let childPlain = dirItem.plainPath.isEmpty ? nameString : "\(dirItem.plainPath)/\(nameString)"

        cacheLock.lock()
        if let cached = pathCache[childPlain] {
            cacheLock.unlock()
            return replyHandler(cached, name, nil)
        }
        cacheLock.unlock()

        let st: ItemStat
        do {
            st = try engine.stat(childPlain)
        } catch {
            return replyHandler(nil, nil, Self.posixError(for: error, default: .ENOENT))
        }

        let type: FSItem.ItemType = st.isDirectory ? .directory : (st.isSymlink ? .symlink : .file)

        let itemID = FSItem.Identifier(rawValue: st.inode) ?? .invalid
        let newItem = GocryptfsItem(
            id: itemID,
            plainPath: childPlain,
            name: nameString,
            itemType: type,
            inode: st.inode,
            parent: dirItem
        )

        cacheLock.lock()
        pathCache[childPlain] = newItem
        cacheLock.unlock()

        replyHandler(newItem, name, nil)
    }

    public func readSymbolicLink(_ item: FSItem, replyHandler: @escaping (FSFileName?, Error?) -> Void) {
        guard let gcItem = item as? GocryptfsItem, gcItem.itemType == .symlink else {
            return replyHandler(nil, POSIXError(.EINVAL))
        }

        do {
            let target = try engine.readlink(gcItem.plainPath)
            replyHandler(FSFileName(string: target), nil)
        } catch {
            logger.error("Failed to readlink for item \(gcItem.name, privacy: .private): \(error.localizedDescription, privacy: .private)")
            replyHandler(nil, Self.posixError(for: error))
        }
    }

    public func enumerateDirectory(_ directory: FSItem,
                                   startingAt cookie: FSDirectoryCookie,
                                   verifier: FSDirectoryVerifier,
                                   attributes: FSItem.GetAttributesRequest?,
                                   packer: FSDirectoryEntryPacker,
                                   replyHandler: @escaping (FSDirectoryVerifier, Error?) -> Void) {
        guard let dirItem = directory as? GocryptfsItem, dirItem.itemType == .directory else {
            return replyHandler(verifier, POSIXError(.ENOTDIR))
        }

        // Every call lists the directory again, so a cookie must not be an
        // index: an entry added or removed between two calls would shift the
        // rest, and the listing would skip or repeat entries. Entries go in the
        // order of a keyed hash of their name (see listingOrder), and a cookie
        // means "continue at the first position not below this". Entries that
        // stay are listed exactly once whatever changes around them.
        let entries: [(position: UInt64, entry: DirEntry)]
        do {
            entries = Self.listingOrder(try engine.list(dirItem.plainPath), key: listingKey)
        } catch {
            logger.error("Failed to list directory: \(error.localizedDescription, privacy: .private)")
            return replyHandler(verifier, Self.posixError(for: error))
        }

        var idx = entries.firstIndex { $0.position >= cookie.rawValue } ?? entries.count
        while idx < entries.count {
            let (position, entry) = entries[idx]
            let nextCookie = FSDirectoryCookie(position + 1)
            let childType: FSItem.ItemType = entry.isDirectory ? .directory : (entry.isSymlink ? .symlink : .file)

            let childPlain = dirItem.plainPath.isEmpty ? entry.name : "\(dirItem.plainPath)/\(entry.name)"
            var childInode: UInt64 = 0

            cacheLock.lock()
            if let cached = pathCache[childPlain] {
                childInode = cached.inode
            }
            cacheLock.unlock()

            var itemAttributes: FSItem.Attributes? = nil
            if childInode == 0 || attributes != nil {
                // The entry may vanish between the listing and this stat. Skip it:
                // FSKit rejects attributes that are missing requested fields.
                guard let st = try? engine.stat(childPlain) else {
                    idx += 1
                    continue
                }
                if childInode == 0 {
                    childInode = st.inode
                }
                if let req = attributes {
                    itemAttributes = makeAttributes(
                        from: st,
                        itemType: childType,
                        inode: childInode,
                        parentInode: dirItem.inode,
                        request: req
                    )
                }
            }

            let itemID = FSItem.Identifier(rawValue: childInode) ?? .invalid

            let ok = packer.packEntry(
                name: FSFileName(string: entry.name),
                itemType: childType,
                itemID: itemID,
                nextCookie: nextCookie,
                attributes: itemAttributes
            )
            if !ok {
                break
            }
            idx += 1
        }

        replyHandler(verifier, nil)
    }

    /// Key of a name in a directory listing: SipHash (Swift's Hasher, seeded at
    /// random per process) of its UTF-8 bytes, in 1...2^54. Unkeyed FNV-1a let
    /// anyone who can name files pick two names with the same key.
    static func listingKey(for name: String) -> UInt64 {
        var hasher = Hasher()
        Array(name.utf8).withUnsafeBytes { hasher.combine(bytes: $0) }
        return (UInt64(bitPattern: Int64(hasher.finalize())) >> 10) + 1
    }

    /// Entries in listing order with the position each one resumes from. Entries
    /// go by key, names that share a key by their bytes; the low 8 bits of a
    /// position count within such a group, so a cookie between two of them
    /// skips neither. Positions start at 2^8 (cookie 0 starts the listing) and
    /// stay below 2^62 + 2^8, so position + 1 fits a cookie.
    static func listingOrder(_ entries: [DirEntry], key: (String) -> UInt64) -> [(position: UInt64, entry: DirEntry)] {
        let keyed = entries.map { (key: key($0.name), entry: $0) }.sorted {
            $0.key != $1.key ? $0.key < $1.key : Array($0.entry.name.utf8).lexicographicallyPrecedes($1.entry.name.utf8)
        }
        var ordered: [(position: UInt64, entry: DirEntry)] = []
        ordered.reserveCapacity(keyed.count)
        var inGroup: UInt64 = 0
        for (i, item) in keyed.enumerated() {
            inGroup = i > 0 && keyed[i - 1].key == item.key ? min(inGroup + 1, 0xff) : 0
            ordered.append((position: item.key << 8 | inGroup, entry: item.entry))
        }
        return ordered
    }

    public func getAttributes(_ desiredAttributes: FSItem.GetAttributesRequest,
                              of item: FSItem,
                              replyHandler: @escaping (FSItem.Attributes?, Error?) -> Void) {
        guard let gcItem = item as? GocryptfsItem else {
            return replyHandler(nil, POSIXError(.EINVAL))
        }

        do {
            replyHandler(try attributes(of: gcItem, request: desiredAttributes), nil)
        } catch {
            // The item is gone (removed here, or by a sync client underneath us).
            // Report that instead of an empty attribute set, which FSKit faults on
            // ("Reported attributes are incomplete") and turns into EINVAL.
            replyHandler(nil, Self.posixError(for: error, default: .ENOENT))
        }
    }

    /// Maps engine errors onto the errno FSKit should hand to the kernel. Every
    /// callback goes through here. The engine's errno passes through as is: the
    /// kernel tells ENOATTR, EEXIST and ERANGE apart (getxattr probes depend on
    /// it), and backup tools skip a file reported as ENOENT.
    static func posixError(for error: Error, default fallback: POSIXError.Code = .EIO) -> POSIXError {
        guard let code = (error as? VaultError)?.posixCode, let posix = POSIXError.Code(rawValue: code) else {
            return POSIXError(fallback)
        }
        return POSIXError(posix)
    }

    /// Attributes of a live item. Throws when the backing file cannot be stat'ed.
    func attributes(of item: GocryptfsItem, request: FSItem.GetAttributesRequest) throws -> FSItem.Attributes {
        let st: ItemStat
        if item.plainPath.isEmpty {
            st = try engine.stat("")
        } else {
            st = try item.withRef { try engine.stat($0) }
        }
        return makeAttributes(
            from: st,
            itemType: item.itemType,
            inode: item.inode,
            parentInode: item.parent?.inode ?? 0,
            request: request
        )
    }

    func makeAttributes(from st: ItemStat,
                        itemType: FSItem.ItemType,
                        inode: UInt64,
                        parentInode: UInt64,
                        request: FSItem.GetAttributesRequest) -> FSItem.Attributes {
        let attrs = FSItem.Attributes()

        if request.isAttributeWanted(.uid) {
            attrs.uid = st.uid
        }
        if request.isAttributeWanted(.gid) {
            attrs.gid = st.gid
        }
        if request.isAttributeWanted(.mode) {
            attrs.mode = st.mode & 0o7777
        }
        if request.isAttributeWanted(.linkCount) {
            attrs.linkCount = st.linkCount
        }
        if request.isAttributeWanted(.flags) {
            attrs.flags = st.flags
        }
        if request.isAttributeWanted(.type) {
            attrs.type = itemType
        }
        if request.isAttributeWanted(.fileID) {
            attrs.fileID = FSItem.Identifier(rawValue: inode != 0 ? inode : st.inode) ?? .invalid
        }
        if request.isAttributeWanted(.parentID) {
            attrs.parentID = FSItem.Identifier(rawValue: parentInode) ?? .invalid
        }

        // The engine already reports plaintext sizes for files and symlinks.
        let plainSize: UInt64 = itemType == .directory ? 4096 : st.size

        if request.isAttributeWanted(.size) {
            attrs.size = plainSize
        }
        if request.isAttributeWanted(.allocSize) {
            attrs.allocSize = ((plainSize + 4095) / 4096) * 4096
        }

        if request.isAttributeWanted(.accessTime) {
            attrs.accessTime = st.accessTime
        }
        if request.isAttributeWanted(.modifyTime) {
            attrs.modifyTime = st.modifyTime
        }
        if request.isAttributeWanted(.changeTime) {
            attrs.changeTime = st.changeTime
        }
        if request.isAttributeWanted(.birthTime) {
            attrs.birthTime = st.birthTime
        }

        return attrs
    }

    // Note: FSVolume.ReadWriteOperations and FSVolume.OpenCloseOperations
    // are implemented in GocryptfsVolume+ReadWrite.swift.
    // Node mutations (create, remove, rename, setAttributes)
    // are implemented in GocryptfsVolume+Mutate.swift.
    // Extended attributes are implemented in GocryptfsVolume+Xattr.swift.

    public func preallocateSpace(for item: FSItem,
                                 at offset: off_t,
                                 length: Int,
                                 flags: FSVolume.PreallocateFlags,
                                 replyHandler: @escaping (Int, Error?) -> Void) {
        replyHandler(0, POSIXError(.ENOTSUP))
    }

    // MARK: - FSVolume.PathConfOperations

    public var maximumLinkCount: Int { 1 }
    public var maximumNameLength: Int { 255 }
    public var restrictsOwnershipChanges: Bool { true }
    public var truncatesLongNames: Bool { false }
    public var maximumFileSizeInBits: Int { 64 }
    /// Maximum individual xattr value size of 64 KiB (2^16). This **must not be 0** —
    /// setting 0 indicates lack of xattr support to the kernel, prompting it to generate
    /// AppleDouble `._name` sidecar files for every file.
    public var maximumXattrSizeInBits: Int { 16 }
}
