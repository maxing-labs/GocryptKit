import Foundation
import FSKit
import OSLog
import VaultCore

private let logger = Logger(subsystem: "com.xwei.GocryptKit.AppEx", category: "Xattr")

// The consequence of omitting this protocol is not simply "no xattr support":
// instead, the kernel synthesizes AppleDouble sidecar files (`._foo`, 4 KiB each) to store them.
// On macOS 14+, every newly created file automatically receives `com.apple.provenance`, which would cause
// every file in the vault to generate an extra 4 KiB companion file that synchronizes across devices.
//
// By implementing this protocol, xattrs are delegated to the engine and stored as native xattrs
// on the underlying ciphertext files (with both names and values encrypted).
extension GocryptfsVolume: FSVolume.XattrOperations {

    public func getXattr(named name: FSFileName,
                         of item: FSItem,
                         replyHandler: @escaping (Data?, (any Error)?) -> Void) {
        guard let gcItem = item as? GocryptfsItem, let attr = name.string else {
            return replyHandler(nil, POSIXError(.EINVAL))
        }
        do {
            replyHandler(try engine.getXattr(gcItem.plainPath, named: attr), nil)
        } catch {
            replyHandler(nil, Self.posixError(from: error, default: .ENOATTR))
        }
    }

    public func setXattr(named name: FSFileName,
                         to value: Data?,
                         on item: FSItem,
                         policy: FSVolume.SetXattrPolicy,
                         replyHandler: @escaping ((any Error)?) -> Void) {
        guard let gcItem = item as? GocryptfsItem, let attr = name.string else {
            return replyHandler(POSIXError(.EINVAL))
        }
        do {
            if policy == .delete {
                try engine.removeXattr(gcItem.plainPath, named: attr)
            } else {
                // Policies other than delete require a non-nil value per protocol contract.
                guard let value else { return replyHandler(POSIXError(.EINVAL)) }
                try engine.setXattr(gcItem.plainPath, named: attr, to: value,
                                    policy: Self.writePolicy(for: policy))
            }
            replyHandler(nil)
        } catch {
            replyHandler(Self.posixError(from: error, default: .EIO))
        }
    }

    public func listXattrs(of item: FSItem,
                           replyHandler: @escaping ([FSFileName]?, (any Error)?) -> Void) {
        guard let gcItem = item as? GocryptfsItem else {
            return replyHandler(nil, POSIXError(.EINVAL))
        }
        do {
            let names = try engine.listXattrs(gcItem.plainPath)
            replyHandler(names.map { FSFileName(string: $0) }, nil)
        } catch {
            replyHandler(nil, Self.posixError(from: error, default: .EIO))
        }
    }

    private static func writePolicy(for policy: FSVolume.SetXattrPolicy) -> XattrWritePolicy {
        switch policy {
        case .mustCreate:  return .mustCreate
        case .mustReplace: return .mustReplace
        default:           return .alwaysSet
        }
    }

    /// The engine propagates underlying errno via `VaultError.ioError(errno)`, which we convert directly
    /// for the kernel — the kernel distinguishes between ENOATTR, EEXIST, and ERANGE, and squashing
    /// them into EIO breaks probe calls in getxattr.
    private static func posixError(from error: any Error, default fallback: POSIXError.Code) -> any Error {
        guard case .ioError(let code)? = error as? VaultError,
              let posix = POSIXError.Code(rawValue: code) else {
            return POSIXError(fallback)
        }
        return POSIXError(posix)
    }
}
