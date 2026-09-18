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
    /// Names and values are encrypted on the ciphertext side: names use EME cipher with an all-zero IV,
    /// while values are encrypted via contentenc. Other attributes (e.g., those native to the underlying APFS)
    /// cannot be read and are not enumerated.
    public func getXattr(_ plain: String, named name: String) throws -> Data {
        let pathCStr = strdup(plain); defer { free(pathCStr) }
        let nameCStr = strdup(name);  defer { free(nameCStr) }

        let needed = gcfc_get_xattr(volumeID, pathCStr, nameCStr, nil, 0)
        if needed < 0 { throw VaultError.ioError(Int32(-needed)) }
        if needed == 0 { return Data() }

        var buffer = [UInt8](repeating: 0, count: Int(needed))
        let n = gcfc_get_xattr(volumeID, pathCStr, nameCStr, &buffer, buffer.count)
        if n < 0 { throw VaultError.ioError(Int32(-n)) }
        return Data(buffer[0..<Int(n)])
    }

    public func setXattr(_ plain: String, named name: String, to value: Data,
                         policy: XattrWritePolicy = .alwaysSet) throws {
        guard value.count <= Self.maximumXattrValueSize else {
            throw VaultError.ioError(E2BIG)
        }
        let pathCStr = strdup(plain); defer { free(pathCStr) }
        let nameCStr = strdup(name);  defer { free(nameCStr) }

        let res = value.withUnsafeBytes { raw in
            gcfc_set_xattr(volumeID, pathCStr, nameCStr,
                           UnsafeMutableRawPointer(mutating: raw.baseAddress),
                           raw.count, policy.rawValue)
        }
        if res != 0 { throw VaultError.ioError(-res) }
    }

    public func removeXattr(_ plain: String, named name: String) throws {
        let pathCStr = strdup(plain); defer { free(pathCStr) }
        let nameCStr = strdup(name);  defer { free(nameCStr) }
        let res = gcfc_remove_xattr(volumeID, pathCStr, nameCStr)
        if res != 0 { throw VaultError.ioError(-res) }
    }

    /// Lists all extended attribute names on this file created by this vault.
    public func listXattrs(_ plain: String) throws -> [String] {
        let pathCStr = strdup(plain); defer { free(pathCStr) }

        let needed = gcfc_list_xattr(volumeID, pathCStr, nil, 0)
        if needed < 0 { throw VaultError.ioError(Int32(-needed)) }
        if needed == 0 { return [] }

        var buffer = [UInt8](repeating: 0, count: Int(needed))
        let n = gcfc_list_xattr(volumeID, pathCStr, &buffer, buffer.count)
        if n < 0 { throw VaultError.ioError(Int32(-n)) }

        // listxattr(2) convention: a sequence of NUL-separated names without trailing sentinel.
        return buffer[0..<Int(n)]
            .split(separator: 0, omittingEmptySubsequences: true)
            .map { String(decoding: $0, as: UTF8.self) }
    }
}
