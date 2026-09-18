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

    let cacheLock = NSLock()
    var pathCache: [String: GocryptfsItem] = [:]
    var inodeCache: [UInt64: GocryptfsItem] = [:]

    init(engine: GocryptfsEngine, cipherURL: URL) throws {
        self.engine = engine
        self.cipherURL = cipherURL

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
        self.inodeCache[rootStat.st_ino] = root

        let volName = FSFileName(string: cipherURL.lastPathComponent + "_gocryptfs")
        super.init(volumeID: FSVolume.Identifier(uuid: UUID()), volumeName: volName)
        logger.info("Initialized GocryptfsVolume for \(cipherURL.path, privacy: .private)")
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
        inodeCache.removeAll()
        cacheLock.unlock()
        engine.shutdown()
        replyHandler()
    }

    public func synchronize(flags: FSSyncFlags, replyHandler: @escaping (Error?) -> Void) {
        // Read-only filesystem has no dirty data
        replyHandler(nil)
    }

    public func setVolumeName(_ name: FSFileName, replyHandler: @escaping (FSFileName?, Error?) -> Void) {
        replyHandler(nil, POSIXError(.ENOTSUP))
    }

    public func reclaimItem(_ item: FSItem, replyHandler: @escaping (Error?) -> Void) {
        guard let gcItem = item as? GocryptfsItem else {
            return replyHandler(POSIXError(.EINVAL))
        }

        cacheLock.lock()
        pathCache.removeValue(forKey: gcItem.plainPath)
        inodeCache.removeValue(forKey: gcItem.inode)
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

        guard let cipherPath = engine.cipherPath(childPlain) else {
            return replyHandler(nil, nil, POSIXError(.ENOENT))
        }

        var st = stat()
        if lstat(cipherPath, &st) != 0 {
            return replyHandler(nil, nil, POSIXError(POSIXError.Code(rawValue: errno) ?? .ENOENT))
        }

        let type: FSItem.ItemType
        switch st.st_mode & S_IFMT {
        case S_IFDIR:
            type = .directory
        case S_IFLNK:
            type = .symlink
        default:
            type = .file
        }

        let itemID = FSItem.Identifier(rawValue: st.st_ino) ?? .invalid
        let newItem = GocryptfsItem(
            id: itemID,
            plainPath: childPlain,
            name: nameString,
            itemType: type,
            inode: st.st_ino,
            parent: dirItem
        )

        cacheLock.lock()
        pathCache[childPlain] = newItem
        inodeCache[st.st_ino] = newItem
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
            replyHandler(nil, POSIXError(.EIO))
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

        let entries: [DirEntry]
        do {
            entries = try engine.list(dirItem.plainPath).sorted(by: { $0.name < $1.name })
        } catch {
            logger.error("Failed to list directory: \(error.localizedDescription, privacy: .private)")
            return replyHandler(verifier, POSIXError(.EIO))
        }

        var idx = Int(cookie.rawValue)
        while idx < entries.count {
            let entry = entries[idx]
            let nextCookie = FSDirectoryCookie(UInt64(idx + 1))
            let childType: FSItem.ItemType = entry.isDirectory ? .directory : (entry.isSymlink ? .symlink : .file)

            let childPlain = dirItem.plainPath.isEmpty ? entry.name : "\(dirItem.plainPath)/\(entry.name)"
            var childInode: UInt64 = 0

            cacheLock.lock()
            if let cached = pathCache[childPlain] {
                childInode = cached.inode
            }
            cacheLock.unlock()

            if childInode == 0, let cipherPath = engine.cipherPath(childPlain) {
                var st = stat()
                if lstat(cipherPath, &st) == 0 {
                    childInode = st.st_ino
                }
            }

            let itemID = FSItem.Identifier(rawValue: childInode) ?? .invalid
            var itemAttributes: FSItem.Attributes? = nil

            if let req = attributes {
                itemAttributes = buildAttributes(
                    forPlainPath: childPlain,
                    itemType: childType,
                    inode: childInode,
                    parentInode: dirItem.inode,
                    request: req
                )
            }

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

    public func getAttributes(_ desiredAttributes: FSItem.GetAttributesRequest,
                              of item: FSItem,
                              replyHandler: @escaping (FSItem.Attributes?, Error?) -> Void) {
        guard let gcItem = item as? GocryptfsItem else {
            return replyHandler(nil, POSIXError(.EINVAL))
        }

        let attrs = buildAttributes(
            forPlainPath: gcItem.plainPath,
            itemType: gcItem.itemType,
            inode: gcItem.inode,
            parentInode: gcItem.parent?.inode ?? 0,
            request: desiredAttributes
        )
        replyHandler(attrs, nil)
    }

    func buildAttributes(forPlainPath plainPath: String,
                         itemType: FSItem.ItemType,
                         inode: UInt64,
                         parentInode: UInt64,
                         request: FSItem.GetAttributesRequest) -> FSItem.Attributes {
        let attrs = FSItem.Attributes()
        let cipherPath: String
        if plainPath.isEmpty {
            cipherPath = cipherURL.path
        } else if let cPath = engine.cipherPath(plainPath) {
            cipherPath = cPath
        } else {
            return attrs
        }

        var st = stat()
        guard lstat(cipherPath, &st) == 0 else {
            return attrs
        }

        if request.isAttributeWanted(.uid) {
            attrs.uid = st.st_uid
        }
        if request.isAttributeWanted(.gid) {
            attrs.gid = st.st_gid
        }
        if request.isAttributeWanted(.mode) {
            attrs.mode = UInt32(Int32(st.st_mode) & 0o7777)
        }
        if request.isAttributeWanted(.linkCount) {
            attrs.linkCount = UInt32(st.st_nlink)
        }
        if request.isAttributeWanted(.flags) {
            attrs.flags = st.st_flags
        }
        if request.isAttributeWanted(.type) {
            attrs.type = itemType
        }
        if request.isAttributeWanted(.fileID) {
            attrs.fileID = FSItem.Identifier(rawValue: inode != 0 ? inode : st.st_ino) ?? .invalid
        }
        if request.isAttributeWanted(.parentID) {
            attrs.parentID = FSItem.Identifier(rawValue: parentInode) ?? .invalid
        }

        // Plain size calculation
        let plainSize: UInt64
        switch itemType {
        case .directory:
            plainSize = 4096
        case .symlink:
            if let target = try? engine.readlink(plainPath) {
                plainSize = UInt64(target.utf8.count)
            } else {
                plainSize = UInt64(st.st_size)
            }
        default:
            plainSize = engine.plainSize(cipherSize: UInt64(st.st_size))
        }

        if request.isAttributeWanted(.size) {
            attrs.size = plainSize
        }
        if request.isAttributeWanted(.allocSize) {
            attrs.allocSize = ((plainSize + 4095) / 4096) * 4096
        }

        if request.isAttributeWanted(.accessTime) {
            attrs.accessTime = st.st_atimespec
        }
        if request.isAttributeWanted(.modifyTime) {
            attrs.modifyTime = st.st_mtimespec
        }
        if request.isAttributeWanted(.changeTime) {
            attrs.changeTime = st.st_ctimespec
        }
        if request.isAttributeWanted(.birthTime) {
            attrs.birthTime = st.st_birthtimespec
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
