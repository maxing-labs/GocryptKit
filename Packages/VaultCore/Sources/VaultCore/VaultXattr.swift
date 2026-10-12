import Foundation
import libgocryptfs

/// Write policy for `setXattr`, corresponding to `XATTR_CREATE` / `XATTR_REPLACE` in setxattr(2).
public enum XattrWritePolicy: Int32, Sendable {
    case alwaysSet = 0
    case mustCreate = 1
    case mustReplace = 2
}

extension GocryptfsEngine {
    /// Upper bound for a single xattr value, corresponding to the extension's `maximumXattrSizeInBits = 16` declaration.
    public static let maximumXattrValueSize = 64 * 1024

    /// Reads an extended attribute.
    ///
    /// Names and values are encrypted on the ciphertext side: names use the EME cipher with upstream
    /// gocryptfs's fixed IV (entries written with the old all-zero IV are still read), while values
    /// are encrypted via contentenc. Other attributes (e.g., those native to the underlying APFS)
    /// cannot be read and are not enumerated.
    public func getXattr(_ plain: String, named name: String) throws -> Data {
        try getXattr(.path(plain), named: name)
    }

    public func getXattr(_ item: ItemRef, named name: String) throws -> Data {
        try withCItem(item) { pathCStr, handle in
            let nameCStr = strdup(name); defer { free(nameCStr) }

            let needed = gcfc_get_xattr(volumeID, pathCStr, handle, nameCStr, nil, 0)
            try Self.check(needed)
            if needed == 0 { return Data() }

            var buffer = [UInt8](repeating: 0, count: Int(needed))
            let n = gcfc_get_xattr(volumeID, pathCStr, handle, nameCStr, &buffer, buffer.count)
            try Self.check(n)
            return Data(buffer[0..<Int(n)])
        }
    }

    public func setXattr(_ plain: String, named name: String, to value: Data,
                         policy: XattrWritePolicy = .alwaysSet) throws {
        try setXattr(.path(plain), named: name, to: value, policy: policy)
    }

    public func setXattr(_ item: ItemRef, named name: String, to value: Data,
                         policy: XattrWritePolicy = .alwaysSet) throws {
        guard value.count <= Self.maximumXattrValueSize else {
            throw VaultError.posix(E2BIG)
        }
        try withCItem(item) { pathCStr, handle in
            let nameCStr = strdup(name); defer { free(nameCStr) }
            let res = value.withUnsafeBytes { raw in
                gcfc_set_xattr(volumeID, pathCStr, handle, nameCStr,
                               UnsafeMutableRawPointer(mutating: raw.baseAddress),
                               raw.count, policy.rawValue)
            }
            try Self.check(res)
        }
    }

    public func removeXattr(_ plain: String, named name: String) throws {
        try removeXattr(.path(plain), named: name)
    }

    public func removeXattr(_ item: ItemRef, named name: String) throws {
        try withCItem(item) { pathCStr, handle in
            let nameCStr = strdup(name); defer { free(nameCStr) }
            let res = gcfc_remove_xattr(volumeID, pathCStr, handle, nameCStr)
            try Self.check(res)
        }
    }

    public func listXattrs(_ plain: String) throws -> [String] {
        try listXattrs(.path(plain))
    }

    /// Lists all extended attribute names on this file created by this vault.
    public func listXattrs(_ item: ItemRef) throws -> [String] {
        try withCItem(item) { pathCStr, handle in
            let needed = gcfc_list_xattr(volumeID, pathCStr, handle, nil, 0)
            try Self.check(needed)
            if needed == 0 { return [] }

            var buffer = [UInt8](repeating: 0, count: Int(needed))
            let n = gcfc_list_xattr(volumeID, pathCStr, handle, &buffer, buffer.count)
            try Self.check(n)

            // listxattr(2) convention: a sequence of NUL-separated names without trailing sentinel.
            return buffer[0..<Int(n)]
                .split(separator: 0, omittingEmptySubsequences: true)
                .map { String(decoding: $0, as: UTF8.self) }
        }
    }
}
