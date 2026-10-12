import Foundation
import FSKit
import OSLog
import VaultCore

final class GocryptfsItem: FSItem, @unchecked Sendable {
    let id: FSItem.Identifier
    let itemType: FSItem.ItemType
    let inode: UInt64

    private let lock = NSLock()
    // A rename rewrites these while other FSKit callbacks read them, so they
    // are only reachable through the lock. Code that already holds `lock`
    // uses the stored properties directly (NSLock is not recursive).
    private var storedPlainPath: String
    private var storedName: String
    private weak var storedParent: GocryptfsItem?

    var plainPath: String {
        lock.lock()
        defer { lock.unlock() }
        return storedPlainPath
    }

    var name: String {
        lock.lock()
        defer { lock.unlock() }
        return storedName
    }

    var parent: GocryptfsItem? {
        lock.lock()
        defer { lock.unlock() }
        return storedParent
    }

    private var readHandle: Int32 = -1
    private var readCount: Int = 0
    private var writeHandle: Int32 = -1
    private var writeCount: Int = 0
    private var openModes: FSVolume.OpenModes = []
    /// Set once the item was removed or replaced by a rename. Its path no longer
    /// names it, so only handles that are already open may be used.
    private var isUnlinked = false
    /// The writable handle createItem opened. A file created read-only (cp of a
    /// 0444 file) cannot be reopened for writing by path, yet the open that
    /// created it may write (POSIX checks permissions on existing files only):
    /// the next write open takes this handle over.
    private var creationHandle: Int32 = -1
    /// The writer is the creation handle, lent to an I/O (a size change) before
    /// any open took it over. Its last release gives it back instead of closing it.
    private var writerIsLentCreation = false
    /// The read mode is held as a writer reference: the file was created without
    /// read permission and only the handle that created it (O_RDWR) can read it.
    private var readThroughWriter = false

    /// A handle borrowed for one I/O. `fromWriter` records which reference to drop.
    struct ReadLease {
        let handle: Int32
        fileprivate let fromWriter: Bool
    }

    init(id: FSItem.Identifier, plainPath: String, name: String, itemType: FSItem.ItemType, inode: UInt64, parent: GocryptfsItem? = nil) {
        self.id = id
        self.storedPlainPath = plainPath
        self.storedName = name
        self.itemType = itemType
        self.inode = inode
        self.storedParent = parent
        super.init()
    }

    func acquireReadHandle(using engine: GocryptfsEngine) throws -> Int32 {
        lock.lock()
        defer { lock.unlock() }

        return try acquireReadHandleLocked(using: engine)
    }

    private func acquireReadHandleLocked(using engine: GocryptfsEngine) throws -> Int32 {
        // Reuse existing read handle
        if readHandle >= 0 {
            readCount += 1
            return readHandle
        }
        guard !isUnlinked else { throw VaultError.posix(ESTALE) }

        let h = try engine.open(storedPlainPath)
        readHandle = h
        readCount = 1
        return h
    }

    /// A write handle for one I/O.
    func acquireWriteHandle(using engine: GocryptfsEngine) throws -> Int32 {
        lock.lock()
        defer { lock.unlock() }

        return try acquireWriteHandleLocked(using: engine, forOpen: false)
    }

    /// `forOpen`: the write mode of an open, which takes the creation handle over
    /// for good. Other callers only borrow it.
    private func acquireWriteHandleLocked(using engine: GocryptfsEngine, forOpen: Bool) throws -> Int32 {
        // Reuse existing write handle
        if writeHandle >= 0 {
            writeCount += 1
            if forOpen { writerIsLentCreation = false }
            return writeHandle
        }
        if creationHandle >= 0 {
            writeHandle = creationHandle
            creationHandle = -1
            writeCount = 1
            writerIsLentCreation = !forOpen
            return writeHandle
        }
        guard !isUnlinked else { throw VaultError.posix(ESTALE) }

        // Open a new write handle independently – do NOT close
        // the read handle; concurrent readers keep working.
        // Never create here: files are created by createItem only, and a
        // reopen with O_CREAT would resurrect a file removed underneath us.
        let h = try engine.openWriteExisting(storedPlainPath)
        writeHandle = h
        writeCount = 1
        return h
    }

    /// Handle for one read. An unlinked item that is only open for writing reads
    /// through its writer (the backing fd is O_RDWR for read-modify-write).
    func acquireReadLease(using engine: GocryptfsEngine) throws -> ReadLease {
        lock.lock()
        defer { lock.unlock() }

        if readHandle < 0 && (isUnlinked || readThroughWriter) && (writeHandle >= 0 || creationHandle >= 0) {
            return ReadLease(handle: try acquireWriteHandleLocked(using: engine, forOpen: false), fromWriter: true)
        }
        return ReadLease(handle: try acquireReadHandleLocked(using: engine), fromWriter: false)
    }

    func release(_ lease: ReadLease, using engine: GocryptfsEngine) {
        if lease.fromWriter {
            releaseWriteHandle(using: engine)
        } else {
            releaseReadHandle(using: engine)
        }
    }

    /// Keeps the handle createItem opened for the write open that follows.
    func keepCreationHandle(_ handle: Int32) {
        lock.lock()
        defer { lock.unlock() }
        creationHandle = handle
    }

    /// The item was removed, or replaced by a rename. Open handles stay valid
    /// until FSKit closes or reclaims the item (POSIX unlink semantics).
    func markUnlinked() {
        lock.lock()
        defer { lock.unlock() }
        markUnlinkedLocked()
    }

    /// Runs `body` with the item's path, or with an open handle once the item is
    /// unlinked (its path may already name a successor). The lock keeps the
    /// handle open meanwhile. Metadata calls (stat, setAttributes, xattrs) go
    /// through here.
    func withRef<T>(_ body: (ItemRef) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }

        guard isUnlinked else { return try body(.path(storedPlainPath)) }
        guard let handle = [writeHandle, readHandle, creationHandle].first(where: { $0 >= 0 }) else {
            throw VaultError.posix(ENOENT)
        }
        return try body(.handle(handle))
    }

    /// Release a read handle previously acquired via acquireReadHandle.
    func releaseReadHandle(using engine: GocryptfsEngine) {
        lock.lock()
        defer { lock.unlock() }

        releaseReadHandleLocked(using: engine)
    }

    private func releaseReadHandleLocked(using engine: GocryptfsEngine) {
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

        releaseWriteHandleLocked(using: engine)
    }

    private func releaseWriteHandleLocked(using engine: GocryptfsEngine) {
        guard writeHandle >= 0 else { return }
        writeCount -= 1
        if writeCount <= 0 {
            if writerIsLentCreation {
                creationHandle = writeHandle
            } else {
                engine.close(writeHandle)
            }
            writerIsLentCreation = false
            writeHandle = -1
            writeCount = 0
        }
    }

    /// FSKit opens modes on an item, rather than one reference per caller.
    func open(modes: FSVolume.OpenModes, using engine: GocryptfsEngine) throws {
        lock.lock()
        defer { lock.unlock() }
        var added: FSVolume.OpenModes = []
        do {
            if modes.contains(.write) && !openModes.contains(.write) {
                _ = try acquireWriteHandleLocked(using: engine, forOpen: true)
                added.insert(.write)
            }
            if modes.contains(.read) && !openModes.contains(.read) {
                try acquireReadModeLocked(using: engine)
                added.insert(.read)
            }
            openModes.formUnion(added)
        } catch {
            if added.contains(.write) { releaseWriteHandleLocked(using: engine) }
            throw error
        }
    }

    /// Holds the read mode. The kernel checks permissions before an open reaches
    /// us, except for the open that creates the file: one created without read
    /// permission (O_CREAT|O_RDWR, 0200) is refused by path and reads through
    /// the handle that created it.
    private func acquireReadModeLocked(using engine: GocryptfsEngine) throws {
        do {
            _ = try acquireReadHandleLocked(using: engine)
        } catch VaultError.posix(EACCES) where writeHandle >= 0 || creationHandle >= 0 {
            _ = try acquireWriteHandleLocked(using: engine, forOpen: false)
            readThroughWriter = true
        }
    }

    private func releaseReadModeLocked(using engine: GocryptfsEngine) {
        if readThroughWriter {
            readThroughWriter = false
            releaseWriteHandleLocked(using: engine)
        } else {
            releaseReadHandleLocked(using: engine)
        }
    }

    /// closeItem supplies the modes to KEEP. Temporary I/O references survive.
    func close(keeping modes: FSVolume.OpenModes, using engine: GocryptfsEngine) {
        lock.lock()
        defer { lock.unlock() }
        // The open that created the item is over: the creation handle is closed
        // now, or on its last release if it is lent out.
        closeCreationHandleLocked(using: engine)
        writerIsLentCreation = false
        if openModes.contains(.read) && !modes.contains(.read) {
            releaseReadModeLocked(using: engine)
            openModes.remove(.read)
        }
        if openModes.contains(.write) && !modes.contains(.write) {
            releaseWriteHandleLocked(using: engine)
            openModes.remove(.write)
        }
    }

    private func closeCreationHandleLocked(using engine: GocryptfsEngine) {
        guard creationHandle >= 0 else { return }
        engine.close(creationHandle)
        creationHandle = -1
    }

    func forceClose(using engine: GocryptfsEngine) {
        lock.lock()
        defer { lock.unlock() }

        openModes = []
        writerIsLentCreation = false
        readThroughWriter = false
        closeCreationHandleLocked(using: engine)
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
        updatePathLocked(plainPath: plainPath, name: name, parent: parent)
    }

    /// Runs `change` with the locks of `items` held, taken in a fixed order so
    /// that two renames in opposite directions cannot deadlock. A rename or a
    /// removal changes what a path names: doing it together with the matching
    /// `markUnlinkedLocked`/`updatePathLocked` keeps `withRef` from resolving an
    /// item's old path to its successor in between. Take no other item's lock
    /// inside (read such paths before).
    static func whileLocked<T>(_ items: [GocryptfsItem], _ change: () throws -> T) rethrows -> T {
        var seen = Set<ObjectIdentifier>()
        let ordered = items.filter { seen.insert(ObjectIdentifier($0)).inserted }
            .sorted { ObjectIdentifier($0) < ObjectIdentifier($1) }
        ordered.forEach { $0.lock.lock() }
        defer { ordered.reversed().forEach { $0.lock.unlock() } }
        return try change()
    }

    /// For `whileLocked` bodies only.
    var lockedPlainPath: String { storedPlainPath }

    /// For `whileLocked` bodies only.
    func markUnlinkedLocked() {
        isUnlinked = true
    }

    /// For `whileLocked` bodies only.
    func updatePathLocked(plainPath: String, name: String, parent: GocryptfsItem?) {
        storedPlainPath = plainPath
        storedName = name
        storedParent = parent
    }
}
