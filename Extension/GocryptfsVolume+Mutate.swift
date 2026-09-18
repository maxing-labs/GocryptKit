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
        guard let dirItem = directory as? GocryptfsItem, let nameString = name.string else {
            return replyHandler(nil, nil, POSIXError(.EINVAL))
        }

        let childPlain = dirItem.plainPath.isEmpty ? nameString : "\(dirItem.plainPath)/\(nameString)"

        switch type {
        case .directory:
            let mode = attributes.isValid(.mode) ? (attributes.mode & 0o7777) : 0o755
            do {
                try engine.mkdir(childPlain, mode: mode)
            } catch {
                logger.error("createItem mkdir failed for \(nameString, privacy: .private): \(error.localizedDescription, privacy: .private)")
                return replyHandler(nil, nil, POSIXError(.EIO))
            }

        case .file:
            let mode = attributes.isValid(.mode) ? (attributes.mode & 0o7777) : 0o644
            do {
                let h = try engine.openWrite(childPlain, mode: mode)
                engine.close(h)
            } catch {
                logger.error("createItem openWrite failed for \(nameString, privacy: .private): \(error.localizedDescription, privacy: .private)")
                return replyHandler(nil, nil, POSIXError(.EIO))
            }

        default:
            return replyHandler(nil, nil, POSIXError(.ENOTSUP))
        }

        guard let cipherPath = engine.cipherPath(childPlain) else {
            return replyHandler(nil, nil, POSIXError(.ENOENT))
        }

        var st = stat()
        guard lstat(cipherPath, &st) == 0 else {
            return replyHandler(nil, nil, POSIXError(POSIXError.Code(rawValue: errno) ?? .ENOENT))
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

        if attributes.isValid(.size) && attributes.size > 0 {
            do {
                _ = try newItem.acquireWriteHandle(using: engine)
                defer { newItem.releaseWriteHandle(using: engine) }
                try engine.truncate(childPlain, size: attributes.size)
            } catch {
                logger.error("createItem truncate failed: \(error.localizedDescription, privacy: .private)")
            }
        }

        replyHandler(newItem, name, nil)
    }

    public func createSymbolicLink(named name: FSFileName,
                                   inDirectory directory: FSItem,
                                   attributes newAttributes: FSItem.SetAttributesRequest,
                                   linkContents contents: FSFileName,
                                   replyHandler: @escaping (FSItem?, FSFileName?, Error?) -> Void) {
        replyHandler(nil, nil, POSIXError(.ENOTSUP))
    }

    public func createLink(to item: FSItem,
                           named name: FSFileName,
                           inDirectory directory: FSItem,
                           replyHandler: @escaping (FSFileName?, Error?) -> Void) {
        replyHandler(nil, POSIXError(.ENOTSUP))
    }

    public func removeItem(_ item: FSItem,
                           named name: FSFileName,
                           fromDirectory directory: FSItem,
                           replyHandler: @escaping (Error?) -> Void) {
        guard let gcItem = item as? GocryptfsItem else {
            return replyHandler(POSIXError(.EINVAL))
        }

        do {
            if gcItem.itemType == .directory {
                try engine.rmdir(gcItem.plainPath)
            } else {
                try engine.remove(gcItem.plainPath)
            }
        } catch let vaultErr as VaultError {
            logger.error("removeItem failed: \(vaultErr.localizedDescription, privacy: .private)")
            switch vaultErr {
            case .notFound:
                return replyHandler(POSIXError(.ENOENT))
            case .ioError(let code):
                return replyHandler(POSIXError(POSIXError.Code(rawValue: code) ?? .EIO))
            default:
                return replyHandler(POSIXError(.EIO))
            }
        } catch {
            return replyHandler(POSIXError(.EIO))
        }

        gcItem.forceClose(using: engine)
        cacheLock.lock()
        pathCache.removeValue(forKey: gcItem.plainPath)
        inodeCache.removeValue(forKey: gcItem.inode)
        if gcItem.itemType == .directory {
            let prefix = gcItem.plainPath + "/"
            let childKeys = pathCache.keys.filter { $0.hasPrefix(prefix) }
            for k in childKeys {
                if let child = pathCache.removeValue(forKey: k) {
                    inodeCache.removeValue(forKey: child.inode)
                    child.forceClose(using: engine)
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
        guard let fromItem = item as? GocryptfsItem,
              let dstDir = destinationDirectory as? GocryptfsItem,
              let dstNameString = destinationName.string else {
            return replyHandler(nil, POSIXError(.EINVAL))
        }

        let oldPlain = fromItem.plainPath
        let newPlain = dstDir.plainPath.isEmpty ? dstNameString : "\(dstDir.plainPath)/\(dstNameString)"

        do {
            try engine.rename(from: oldPlain, to: newPlain)
        } catch let vaultErr as VaultError {
            logger.error("renameItem failed: \(vaultErr.localizedDescription, privacy: .private)")
            switch vaultErr {
            case .notFound:
                return replyHandler(nil, POSIXError(.ENOENT))
            case .ioError(let code):
                return replyHandler(nil, POSIXError(POSIXError.Code(rawValue: code) ?? .EIO))
            default:
                return replyHandler(nil, POSIXError(.EIO))
            }
        } catch {
            return replyHandler(nil, POSIXError(.EIO))
        }

        cacheLock.lock()
        pathCache.removeValue(forKey: oldPlain)
        if let over = overItem as? GocryptfsItem {
            pathCache.removeValue(forKey: over.plainPath)
            inodeCache.removeValue(forKey: over.inode)
            over.forceClose(using: engine)
        }

        fromItem.forceClose(using: engine)
        fromItem.updatePath(plainPath: newPlain, name: dstNameString, parent: dstDir)
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
        guard let gcItem = item as? GocryptfsItem else {
            return replyHandler(nil, POSIXError(.EINVAL))
        }

        if newAttributes.isValid(.size) {
            guard gcItem.itemType == .file else {
                return replyHandler(nil, POSIXError(.EISDIR))
            }
            do {
                _ = try gcItem.acquireWriteHandle(using: engine)
                defer { gcItem.releaseWriteHandle(using: engine) }
                try engine.truncate(gcItem.plainPath, size: newAttributes.size)
            } catch {
                logger.error("setAttributes truncate failed: \(error.localizedDescription, privacy: .private)")
                return replyHandler(nil, POSIXError(.EIO))
            }
        }

        if newAttributes.isValid(.mode) {
            if let cipherPath = engine.cipherPath(gcItem.plainPath) {
                let ret = chmod(cipherPath, mode_t(newAttributes.mode & 0o7777))
                if ret != 0 {
                    let err = errno
                    logger.error("setAttributes chmod failed: errno \(err, privacy: .public)")
                    return replyHandler(nil, POSIXError(POSIXErrorCode(rawValue: err) ?? .EPERM))
                }
            }
        }

        let getAttrRequest = FSItem.GetAttributesRequest()
        getAttrRequest.wantedAttributes = [.gid, .uid, .mode, .size, .allocSize,
                                           .type, .fileID, .parentID, .flags,
                                           .linkCount, .accessTime, .birthTime,
                                           .modifyTime, .changeTime]

        let attrs = buildAttributes(
            forPlainPath: gcItem.plainPath,
            itemType: gcItem.itemType,
            inode: gcItem.inode,
            parentInode: gcItem.parent?.inode ?? 0,
            request: getAttrRequest
        )
        replyHandler(attrs, nil)
    }
}
