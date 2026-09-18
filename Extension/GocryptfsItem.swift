import Foundation
import FSKit
import OSLog
import VaultCore

final class GocryptfsItem: FSItem, @unchecked Sendable {
    let id: FSItem.Identifier
    var plainPath: String
    var name: String
    let itemType: FSItem.ItemType
    let inode: UInt64
    weak var parent: GocryptfsItem?

    private let lock = NSLock()
    private var readHandle: Int32 = -1
    private var readCount: Int = 0
    private var writeHandle: Int32 = -1
    private var writeCount: Int = 0

    init(id: FSItem.Identifier, plainPath: String, name: String, itemType: FSItem.ItemType, inode: UInt64, parent: GocryptfsItem? = nil) {
        self.id = id
        self.plainPath = plainPath
        self.name = name
        self.itemType = itemType
        self.inode = inode
        self.parent = parent
        super.init()
    }

    func acquireReadHandle(using engine: GocryptfsEngine) throws -> Int32 {
        lock.lock()
        defer { lock.unlock() }

        // Reuse existing read handle
        if readHandle >= 0 {
            readCount += 1
            return readHandle
        }

        let h = try engine.open(plainPath)
        readHandle = h
        readCount = 1
        return h
    }

    func acquireWriteHandle(using engine: GocryptfsEngine, mode: UInt32 = 0o644) throws -> Int32 {
        lock.lock()
        defer { lock.unlock() }

        // Reuse existing write handle
        if writeHandle >= 0 {
            writeCount += 1
            return writeHandle
        }

        // Open a new write handle independently – do NOT close
        // the read handle; concurrent readers keep working.
        let h = try engine.openWrite(plainPath, mode: mode)
        writeHandle = h
        writeCount = 1
        return h
    }

    func acquireHandle(using engine: GocryptfsEngine) throws -> Int32 {
        try acquireReadHandle(using: engine)
    }

    /// Release a read handle previously acquired via acquireReadHandle.
    func releaseReadHandle(using engine: GocryptfsEngine) {
        lock.lock()
        defer { lock.unlock() }

        guard readHandle >= 0 else { return }
        readCount -= 1
        if readCount <= 0 {
            engine.close(readHandle)
            readHandle = -1
            readCount = 0
        }
    }

    /// Release a write handle previously acquired via acquireWriteHandle.
    func releaseWriteHandle(using engine: GocryptfsEngine) {
        lock.lock()
        defer { lock.unlock() }

        guard writeHandle >= 0 else { return }
        writeCount -= 1
        if writeCount <= 0 {
            engine.close(writeHandle)
            writeHandle = -1
            writeCount = 0
        }
    }

    /// Backward-compatible release for callers that don't distinguish
    /// read vs write. Tries write first (since it's the newer path),
    /// then read.
    func releaseHandle(using engine: GocryptfsEngine) {
        lock.lock()
        defer { lock.unlock() }

        // Prefer closing write handles first
        if writeHandle >= 0 && writeCount > 0 {
            writeCount -= 1
            if writeCount <= 0 {
                engine.close(writeHandle)
                writeHandle = -1
                writeCount = 0
            }
            return
        }

        if readHandle >= 0 {
            readCount -= 1
            if readCount <= 0 {
                engine.close(readHandle)
                readHandle = -1
                readCount = 0
            }
        }
    }

    func forceClose(using engine: GocryptfsEngine) {
        lock.lock()
        defer { lock.unlock() }

        if readHandle >= 0 {
            engine.close(readHandle)
            readHandle = -1
            readCount = 0
        }
        if writeHandle >= 0 {
            engine.close(writeHandle)
            writeHandle = -1
            writeCount = 0
        }
    }

    func updatePath(plainPath: String, name: String, parent: GocryptfsItem?) {
        lock.lock()
        defer { lock.unlock() }
        self.plainPath = plainPath
        self.name = name
        self.parent = parent
    }
}
