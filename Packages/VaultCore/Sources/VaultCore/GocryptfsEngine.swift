import Foundation
import libgocryptfs

public final class GocryptfsEngine: VaultEngine, @unchecked Sendable {
    public let volumeID: Int32
    private let lock = NSLock()
    private var isShutdown = false

    public convenience init(cipherDir: URL, credential: VaultCredential) throws {
        var dummy: Data? = nil
        try self.init(cipherDir: cipherDir, credential: credential, returnedScryptHash: &dummy)
    }

    public init(cipherDir: URL, credential: VaultCredential, returnedScryptHash: inout Data?) throws {
        let dirPath = cipherDir.path
        var hashBuffer = [UInt8](repeating: 0, count: 32)
        var volID: Int32 = -1

        let dirCStr = strdup(dirPath)
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
            volID = gcfc_init(dirCStr, pwdCStr, nil, 0, &hashBuffer, hashBuffer.count)
        case .scryptHash(var hash):
            hash.withUnsafeMutableBytes { buf in
                guard let base = buf.baseAddress else { return }
                volID = gcfc_init(dirCStr, nil, base.assumingMemoryBound(to: UInt8.self), buf.count, &hashBuffer, hashBuffer.count)
                memset_s(base, buf.count, 0, buf.count)
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
        returnedScryptHash = Data(hashBuffer)
        // Wipe the temporary buffer now that Data has its own copy.
        for i in hashBuffer.indices { hashBuffer[i] = 0 }
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

    public func list(_ plainDir: String) throws -> [DirEntry] {
        lock.lock()
        guard !isShutdown else {
            lock.unlock()
            throw VaultError.isClosed
        }
        lock.unlock()

        let dirCStr = strdup(plainDir)
        defer { free(dirCStr) }

        var entriesPtr: UnsafeMutablePointer<gcfc_dir_entry_t>? = nil
        var count: Int32 = 0

        let res = gcfc_list_dir(volumeID, dirCStr, &entriesPtr, &count)
        if res != 0 {
            if res == -ENOENT {
                throw VaultError.notFound(plainDir)
            }
            throw VaultError.ioError(-res)
        }

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

    public func cipherPath(_ plain: String) -> String? {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }

        guard let cPathPtr = gcfc_cipher_path(volumeID, plainCStr) else {
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

        guard let targetPtr = gcfc_readlink(volumeID, plainCStr) else {
            throw VaultError.notFound(plain)
        }
        defer { gcfc_free_string(targetPtr) }
        return String(cString: targetPtr)
    }

    public func open(_ plain: String) throws -> Int32 {
        lock.lock()
        guard !isShutdown else {
            lock.unlock()
            throw VaultError.isClosed
        }
        lock.unlock()

        let plainCStr = strdup(plain)
        defer { free(plainCStr) }

        let handle = gcfc_open_read_mode(volumeID, plainCStr)
        if handle < 0 {
            throw VaultError.notFound(plain)
        }
        return handle
    }

    public func openWrite(_ plain: String, mode: UInt32 = 0o644) throws -> Int32 {
        lock.lock()
        guard !isShutdown else {
            lock.unlock()
            throw VaultError.isClosed
        }
        lock.unlock()

        let plainCStr = strdup(plain)
        defer { free(plainCStr) }

        let handle = gcfc_open_write_mode(volumeID, plainCStr, mode)
        if handle < 0 {
            throw VaultError.notFound(plain)
        }
        return handle
    }

    public func read(_ h: Int32, offset: UInt64, into buffer: UnsafeMutableRawBufferPointer) throws -> Int {
        try read(h, offset: offset, into: buffer, length: buffer.count)
    }

    public func read(_ h: Int32, offset: UInt64, into buffer: UnsafeMutableRawBufferPointer, length: Int) throws -> Int {
        guard let baseAddress = buffer.baseAddress else { return 0 }
        let toRead = min(length, buffer.count)
        guard toRead > 0 else { return 0 }
        let bytesRead = gcfc_read_file(volumeID, h, offset, baseAddress, toRead)
        if bytesRead < 0 {
            throw VaultError.ioError(Int32(-bytesRead))
        }
        return Int(bytesRead)
    }

    public func write(_ h: Int32, offset: UInt64, from buffer: UnsafeRawBufferPointer) throws -> Int {
        guard let baseAddress = buffer.baseAddress else { return 0 }
        let bytesWritten = gcfc_write_file(volumeID, h, offset, UnsafeMutableRawPointer(mutating: baseAddress), buffer.count)
        if bytesWritten < 0 {
            throw VaultError.ioError(Int32(-bytesWritten))
        }
        return Int(bytesWritten)
    }

    public func truncate(_ plain: String, size: UInt64) throws {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }
        let res = gcfc_truncate(volumeID, plainCStr, size)
        if res != 0 {
            throw VaultError.ioError(-res)
        }
    }

    public func remove(_ plain: String) throws {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }
        let res = gcfc_remove_file(volumeID, plainCStr)
        if res != 0 {
            throw VaultError.ioError(-res)
        }
    }

    public func mkdir(_ plain: String, mode: UInt32 = 0o755) throws {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }
        let res = gcfc_mkdir(volumeID, plainCStr, mode)
        if res != 0 {
            throw VaultError.ioError(-res)
        }
    }

    public func rmdir(_ plain: String) throws {
        let plainCStr = strdup(plain)
        defer { free(plainCStr) }
        let res = gcfc_rmdir(volumeID, plainCStr)
        if res != 0 {
            throw VaultError.ioError(-res)
        }
    }

    public func rename(from oldPath: String, to newPath: String) throws {
        let oldCStr = strdup(oldPath)
        defer { free(oldCStr) }
        let newCStr = strdup(newPath)
        defer { free(newCStr) }
        let res = gcfc_rename(volumeID, oldCStr, newCStr)
        if res != 0 {
            throw VaultError.ioError(-res)
        }
    }

    public func close(_ h: Int32) {
        gcfc_close_file(volumeID, h)
    }
}
