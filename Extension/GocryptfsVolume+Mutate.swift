import Foundation
import ExtensionFoundation
import FSKit
import OSLog
import VaultCore

private let logger = Logger(subsystem: "com.xwei.GocryptKit.AppEx", category: "GocryptfsVolume+Mutate")

extension GocryptfsVolume {

    // MARK: - Mutation Operations

    public func createItem(named name: FSFileName,
                           type: FSItem.ItemType,
                           inDirectory directory: FSItem,
                           attributes: FSItem.SetAttributesRequest,
                           replyHandler: @escaping (FSItem?, FSFileName?, Error?) -> Void) {
        guard !isReadOnly else {
            return replyHandler(nil, nil, POSIXError(.EROFS))
        }
        guard let dirItem = directory as? GocryptfsItem, let nameString = name.string else {
            return replyHandler(nil, nil, POSIXError(.EINVAL))
        }

        let childPlain = dirItem.plainPath.isEmpty ? nameString : "\(dirItem.plainPath)/\(nameString)"
        // A new file's writable handle, handed to the item for the open that follows.
        var creationHandle: Int32 = -1

        switch type {
        case .directory:
            let mode = attributes.isValid(.mode) ? (attributes.mode & 0o7777) : 0o755
            do {
                try engine.mkdir(childPlain, mode: mode)
            } catch {
                logger.error("createItem mkdir failed for \(nameString, privacy: .private): \(error.localizedDescription, privacy: .private)")
                return replyHandler(nil, nil, Self.posixError(for: error))
            }

        case .file:
            let mode = attributes.isValid(.mode) ? (attributes.mode & 0o7777) : 0o644
            do {
                // Exclusive: two racing creates of one name (lock files) must not
                // both succeed, and an existing file must never be reopened here.
                creationHandle = try engine.createFile(childPlain, mode: mode)
            } catch {
                logger.error("createItem create failed for \(nameString, privacy: .private): \(error.localizedDescription, privacy: .private)")
                return replyHandler(nil, nil, Self.posixError(for: error))
            }

        default:
            return replyHandler(nil, nil, POSIXError(.ENOTSUP))
        }

        if creationHandle >= 0, attributes.isValid(.size), attributes.size > 0 {
            // A file that could not be given its requested size must not be
            // reported as created: undo it and pass the error on.
            do {
                try engine.truncate(creationHandle, size: attributes.size)
            } catch {
                logger.error("createItem truncate failed: \(error.localizedDescription, privacy: .private)")
                engine.close(creationHandle)
                try? engine.remove(childPlain)
                return replyHandler(nil, nil, Self.posixError(for: error))
            }
        }

        let st: ItemStat
        do {
            st = try engine.stat(childPlain)
        } catch {
            if creationHandle >= 0 { engine.close(creationHandle) }
            return replyHandler(nil, nil, Self.posixError(for: error, default: .ENOENT))
        }

        let itemID = FSItem.Identifier(rawValue: st.inode) ?? .invalid
        let newItem = GocryptfsItem(
            id: itemID,
            plainPath: childPlain,
            name: nameString,
            itemType: type,
            inode: st.inode,
            parent: dirItem
        )
        if creationHandle >= 0 {
            newItem.keepCreationHandle(creationHandle)
        }

        cacheLock.lock()
        pathCache[childPlain] = newItem
        cacheLock.unlock()

        replyHandler(newItem, name, nil)
    }

    public func createSymbolicLink(named name: FSFileName,
                                   inDirectory directory: FSItem,
                                   attributes newAttributes: FSItem.SetAttributesRequest,
                                   linkContents contents: FSFileName,
                                   replyHandler: @escaping (FSItem?, FSFileName?, Error?) -> Void) {
        if isReadOnly {
            return replyHandler(nil, nil, POSIXError(.EROFS))
        }
        replyHandler(nil, nil, POSIXError(.ENOTSUP))
    }

    public func createLink(to item: FSItem,
                           named name: FSFileName,
                           inDirectory directory: FSItem,
                           replyHandler: @escaping (FSFileName?, Error?) -> Void) {
        if isReadOnly {
            return replyHandler(nil, POSIXError(.EROFS))
        }
        replyHandler(nil, POSIXError(.ENOTSUP))
    }

    public func removeItem(_ item: FSItem,
                           named name: FSFileName,
                           fromDirectory directory: FSItem,
                           replyHandler: @escaping (Error?) -> Void) {
        guard !isReadOnly else {
            return replyHandler(POSIXError(.EROFS))
        }
        guard let gcItem = item as? GocryptfsItem else {
            return replyHandler(POSIXError(.EINVAL))
        }

        do {
            // Keep the handles: a process that still has the file open goes on
            // reading and writing the unlinked inode until FSKit closes or reclaims
            // the item. Closing them here made the next write reopen by path and
            // resurrect the file (or write into whatever took over the name).
            try GocryptfsItem.whileLocked([gcItem]) {
                if gcItem.itemType == .directory {
                    try engine.rmdir(gcItem.lockedPlainPath)
                } else {
                    try engine.remove(gcItem.lockedPlainPath)
                }
                gcItem.markUnlinkedLocked()
            }
        } catch {
            logger.error("removeItem failed: \(error.localizedDescription, privacy: .private)")
            return replyHandler(Self.posixError(for: error))
        }

        cacheLock.lock()
        pathCache.removeValue(forKey: gcItem.plainPath)
        if gcItem.itemType == .directory {
            let prefix = gcItem.plainPath + "/"
            let childKeys = pathCache.keys.filter { $0.hasPrefix(prefix) }
            for k in childKeys {
                if let child = pathCache.removeValue(forKey: k) {
                    child.markUnlinked()
                }
            }
        }
        cacheLock.unlock()

        replyHandler(nil)
    }

    public func renameItem(_ item: FSItem,
                           inDirectory sourceDirectory: FSItem,
                           named sourceName: FSFileName,
                           to destinationName: FSFileName,
                           inDirectory destinationDirectory: FSItem,
                           overItem: FSItem?,
                           replyHandler: @escaping (FSFileName?, Error?) -> Void) {
        guard !isReadOnly else {
            return replyHandler(nil, POSIXError(.EROFS))
        }
        guard let fromItem = item as? GocryptfsItem,
              let dstDir = destinationDirectory as? GocryptfsItem,
              let dstNameString = destinationName.string else {
            return replyHandler(nil, POSIXError(.EINVAL))
        }

        let newPlain = dstDir.plainPath.isEmpty ? dstNameString : "\(dstDir.plainPath)/\(dstNameString)"
        let over = overItem as? GocryptfsItem

        // The replaced item becomes an unlinked inode for whoever has it open, and
        // open handles follow the moved item's inode. Both are marked in the same
        // step as the rename, so neither resolves its old path to the other file.
        let oldPlain: String
        do {
            oldPlain = try GocryptfsItem.whileLocked([fromItem] + (over.map { [$0] } ?? [])) {
                let oldPlain = fromItem.lockedPlainPath
                try engine.rename(from: oldPlain, to: newPlain)
                over?.markUnlinkedLocked()
                fromItem.updatePathLocked(plainPath: newPlain, name: dstNameString, parent: dstDir)
                return oldPlain
            }
        } catch {
            logger.error("renameItem failed: \(error.localizedDescription, privacy: .private)")
            return replyHandler(nil, Self.posixError(for: error))
        }

        cacheLock.lock()
        pathCache.removeValue(forKey: oldPlain)
        if let over {
            pathCache.removeValue(forKey: over.plainPath)
        }
        pathCache[newPlain] = fromItem

        if fromItem.itemType == .directory {
            let oldPrefix = oldPlain + "/"
            let newPrefix = newPlain + "/"
            let childKeys = pathCache.keys.filter { $0.hasPrefix(oldPrefix) }
            for k in childKeys {
                if let child = pathCache.removeValue(forKey: k) {
                    let suffix = String(k.dropFirst(oldPrefix.count))
                    let childNewPlain = newPrefix + suffix
                    child.updatePath(plainPath: childNewPlain, name: child.name, parent: child.parent)
                    pathCache[childNewPlain] = child
                }
            }
        }
        cacheLock.unlock()

        replyHandler(destinationName, nil)
    }

    public func setAttributes(_ newAttributes: FSItem.SetAttributesRequest,
                              on item: FSItem,
                              replyHandler: @escaping (FSItem.Attributes?, Error?) -> Void) {
        guard !isReadOnly else {
            return replyHandler(nil, POSIXError(.EROFS))
        }
        guard let gcItem = item as? GocryptfsItem else {
            return replyHandler(nil, POSIXError(.EINVAL))
        }

        // FSKit: ignore the size of directories and symlinks, without an error.
        if newAttributes.isValid(.size), gcItem.itemType == .file {
            do {
                let handle = try gcItem.acquireWriteHandle(using: engine)
                defer { gcItem.releaseWriteHandle(using: engine) }
                try engine.truncate(handle, size: newAttributes.size)
            } catch {
                logger.error("setAttributes truncate failed: \(error.localizedDescription, privacy: .private)")
                return replyHandler(nil, Self.posixError(for: error))
            }
            newAttributes.consumedAttributes.insert(.size)
        }

        // Through the engine: dirfd-relative and never following a symlink.
        // chmod(2) on the ciphertext path string would follow one planted as
        // the last component and change a file outside the vault.
        var changes = AttributeChanges()
        var consumed: FSItem.Attribute = []
        if newAttributes.isValid(.mode) {
            changes.mode = newAttributes.mode & 0o7777
            consumed.insert(.mode)
        }
        if newAttributes.isValid(.uid) {
            changes.uid = newAttributes.uid
            consumed.insert(.uid)
        }
        if newAttributes.isValid(.gid) {
            changes.gid = newAttributes.gid
            consumed.insert(.gid)
        }
        if newAttributes.isValid(.flags) {
            changes.flags = newAttributes.flags
            consumed.insert(.flags)
        }
        if newAttributes.isValid(.accessTime) {
            changes.accessTime = newAttributes.accessTime
            consumed.insert(.accessTime)
        }
        if newAttributes.isValid(.modifyTime) {
            changes.modifyTime = newAttributes.modifyTime
            consumed.insert(.modifyTime)
        }
        if newAttributes.isValid(.birthTime) {
            changes.birthTime = newAttributes.birthTime
            consumed.insert(.birthTime)
        }
        if !changes.isEmpty {
            do {
                try gcItem.withRef { try engine.setAttributes($0, changes) }
            } catch {
                logger.error("setAttributes failed: \(error.localizedDescription, privacy: .private)")
                return replyHandler(nil, Self.posixError(for: error, default: .EPERM))
            }
            newAttributes.consumedAttributes.formUnion(consumed)
        }

        let getAttrRequest = FSItem.GetAttributesRequest()
        getAttrRequest.wantedAttributes = [.gid, .uid, .mode, .size, .allocSize,
                                           .type, .fileID, .parentID, .flags,
                                           .linkCount, .accessTime, .birthTime,
                                           .modifyTime, .changeTime]

        do {
            replyHandler(try attributes(of: gcItem, request: getAttrRequest), nil)
        } catch {
            replyHandler(nil, Self.posixError(for: error, default: .ENOENT))
        }
    }
}
