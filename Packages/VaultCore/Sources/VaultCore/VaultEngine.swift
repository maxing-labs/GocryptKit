import Foundation

public enum VaultCredential {
    case password(String)
    case scryptHash(Data)
}

public struct DirEntry: Sendable, Equatable {
    public let name: String
    public let mode: UInt32

    public init(name: String, mode: UInt32) {
        self.name = name
        self.mode = mode
    }

    public var isDirectory: Bool {
        (mode & UInt32(S_IFMT)) == UInt32(S_IFDIR)
    }

    public var isRegularFile: Bool {
        (mode & UInt32(S_IFMT)) == UInt32(S_IFREG)
    }

    public var isSymlink: Bool {
        (mode & UInt32(S_IFMT)) == UInt32(S_IFLNK)
    }
}

public enum VaultError: LocalizedError, Equatable {
    case invalidCipherDir
    case configNotFound
    case authFailed
    case notFound(String)
    case ioError(Int32)
    case isClosed
    case badHandle
    case emptyPassword
    case vaultAlreadyExists
    case directoryNotEmpty
    case invalidScryptLogN
    case initFailed(Int32)

    public var errorDescription: String? {
        switch self {
        case .invalidCipherDir:
            return "Invalid cipher directory path"
        case .configNotFound:
            return "gocryptfs.conf not found or corrupted"
        case .authFailed:
            return "Authentication failed: invalid password or masterkey"
        case .notFound(let path):
            return "File or directory not found: \(path)"
        case .ioError(let code):
            return "I/O error with errno \(code)"
        case .isClosed:
            return "Vault is closed"
        case .badHandle:
            return "Bad file handle"
        case .emptyPassword:
            return "A vault password is required; refusing to create a vault without one"
        case .vaultAlreadyExists:
            return "This directory already holds a gocryptfs vault (gocryptfs.conf present)"
        case .directoryNotEmpty:
            return "The directory is not empty; a new vault needs an empty directory"
        case .invalidScryptLogN:
            return "scrypt logN is out of range (allowed: 10...31, or 0 for the default)"
        case .initFailed(let code):
            return "Vault creation failed (engine status \(code))"
        }
    }
}

public protocol VaultEngine: Sendable {
    init(cipherDir: URL, credential: VaultCredential, returnedScryptHash: inout Data?) throws
    func list(_ plainDir: String) throws -> [DirEntry]
    func cipherPath(_ plain: String) -> String?
    func plainSize(cipherSize: UInt64) -> UInt64
    func readlink(_ plain: String) throws -> String
    func open(_ plain: String) throws -> Int32
    func read(_ h: Int32, offset: UInt64, into buffer: UnsafeMutableRawBufferPointer) throws -> Int
    func read(_ h: Int32, offset: UInt64, into buffer: UnsafeMutableRawBufferPointer, length: Int) throws -> Int
    func write(_ h: Int32, offset: UInt64, from buffer: UnsafeRawBufferPointer) throws -> Int
    func truncate(_ plain: String, size: UInt64) throws
    func remove(_ plain: String) throws
    func mkdir(_ plain: String, mode: UInt32) throws
    func rmdir(_ plain: String) throws
    func rename(from oldPath: String, to newPath: String) throws
    func close(_ h: Int32)
    func shutdown()
}
