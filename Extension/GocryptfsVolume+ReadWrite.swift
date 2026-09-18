import Foundation
import ExtensionFoundation
import FSKit
import OSLog
import VaultCore

private let logger = Logger(subsystem: "com.xwei.GocryptKit.AppEx", category: "GocryptfsVolume+ReadWrite")

extension GocryptfsVolume {

    // MARK: - FSVolume.ReadWriteOperations

    public func read(from item: FSItem,
                     at offset: off_t,
                     length: Int,
                     into buffer: FSMutableFileDataBuffer,
                     replyHandler: @escaping (Int, Error?) -> Void) {
        guard let gcItem = item as? GocryptfsItem, gcItem.itemType == .file else {
            return replyHandler(0, POSIXError(.EINVAL))
        }
        guard offset >= 0, length >= 0 else {
            return replyHandler(0, POSIXError(.EINVAL))
        }
        if length == 0 {
            return replyHandler(0, nil)
        }

        let handle: Int32
        do {
            handle = try gcItem.acquireReadHandle(using: engine)
        } catch {
            logger.error("Failed to open file for read: \(error.localizedDescription, privacy: .private)")
            return replyHandler(0, POSIXError(.EIO))
        }
        defer { gcItem.releaseReadHandle(using: engine) }

        var readBytes = 0
        var readError: Error?

        buffer.withUnsafeMutableBytes { rawBuf in
            guard let baseAddress = rawBuf.baseAddress else { return }
            let bytesToRead = min(length, rawBuf.count)
            guard bytesToRead > 0 else { return }
            let subBuffer = UnsafeMutableRawBufferPointer(start: baseAddress, count: bytesToRead)
            do {
                readBytes = try engine.read(handle, offset: UInt64(offset), into: subBuffer, length: bytesToRead)
            } catch {
                readError = error
            }
        }

        if let err = readError {
            logger.error("Failed to read decrypted data: \(err.localizedDescription, privacy: .private)")
            return replyHandler(0, POSIXError(.EIO))
        }

        replyHandler(readBytes, nil)
    }

    public func write(contents: Data,
                      to item: FSItem,
                      at offset: off_t,
                      replyHandler: @escaping (Int, Error?) -> Void) {
        guard let gcItem = item as? GocryptfsItem else {
            return replyHandler(0, POSIXError(.EINVAL))
        }
        guard gcItem.itemType != .directory else {
            return replyHandler(0, POSIXError(.EISDIR))
        }
        guard offset >= 0 else {
            return replyHandler(0, POSIXError(.EINVAL))
        }

        let handle: Int32
        do {
            handle = try gcItem.acquireWriteHandle(using: engine)
        } catch {
            logger.error("Failed to acquire write handle for write: \(error.localizedDescription, privacy: .private)")
            return replyHandler(0, POSIXError(.EIO))
        }
        defer { gcItem.releaseWriteHandle(using: engine) }

        var written = 0
        var writeError: Error?

        contents.withUnsafeBytes { rawBuf in
            do {
                written = try engine.write(handle, offset: UInt64(offset), from: rawBuf)
            } catch {
                writeError = error
            }
        }

        if let err = writeError {
            logger.error("engine.write failed: \(err.localizedDescription, privacy: .private)")
            return replyHandler(0, POSIXError(.EIO))
        }

        replyHandler(written, nil)
    }

    // MARK: - FSVolume.OpenCloseOperations

    public func openItem(_ item: FSItem,
                         modes: FSVolume.OpenModes,
                         replyHandler: @escaping (Error?) -> Void) {
        guard let gcItem = item as? GocryptfsItem else {
            return replyHandler(POSIXError(.EINVAL))
        }

        if gcItem.itemType == .file {
            do {
                if modes.contains(.write) {
                    _ = try gcItem.acquireWriteHandle(using: engine)
                } else {
                    _ = try gcItem.acquireReadHandle(using: engine)
                }
                replyHandler(nil)
            } catch {
                logger.error("openItem failed for \(gcItem.name, privacy: .private): \(error.localizedDescription, privacy: .private)")
                replyHandler(POSIXError(.EIO))
            }
        } else {
            replyHandler(nil)
        }
    }

    public func closeItem(_ item: FSItem,
                          modes: FSVolume.OpenModes,
                          replyHandler: @escaping (Error?) -> Void) {
        guard let gcItem = item as? GocryptfsItem else {
            return replyHandler(POSIXError(.EINVAL))
        }

        if gcItem.itemType == .file {
            if modes.contains(.write) {
                gcItem.releaseWriteHandle(using: engine)
            } else {
                gcItem.releaseReadHandle(using: engine)
            }
        }
        replyHandler(nil)
    }
}
