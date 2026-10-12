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
            replyHandler(try gcItem.withRef { try engine.getXattr($0, named: attr) }, nil)
        } catch {
            replyHandler(nil, Self.posixError(for: error))
        }
    }

    public func setXattr(named name: FSFileName,
                         to value: Data?,
                         on item: FSItem,
                         policy: FSVolume.SetXattrPolicy,
                         replyHandler: @escaping ((any Error)?) -> Void) {
        guard !isReadOnly else {
            return replyHandler(POSIXError(.EROFS))
        }
        guard let gcItem = item as? GocryptfsItem, let attr = name.string else {
            return replyHandler(POSIXError(.EINVAL))
        }
        do {
            if policy == .delete {
                try gcItem.withRef { try engine.removeXattr($0, named: attr) }
            } else {
                // Policies other than delete require a non-nil value per protocol contract.
                guard let value else { return replyHandler(POSIXError(.EINVAL)) }
                try gcItem.withRef {
                    try engine.setXattr($0, named: attr, to: value, policy: Self.writePolicy(for: policy))
                }
            }
            replyHandler(nil)
        } catch {
            replyHandler(Self.posixError(for: error))
        }
    }

    public func listXattrs(of item: FSItem,
                           replyHandler: @escaping ([FSFileName]?, (any Error)?) -> Void) {
        guard let gcItem = item as? GocryptfsItem else {
            return replyHandler(nil, POSIXError(.EINVAL))
        }
        do {
            let names = try gcItem.withRef { try engine.listXattrs($0) }
            replyHandler(names.map { FSFileName(string: $0) }, nil)
        } catch {
            replyHandler(nil, Self.posixError(for: error))
        }
    }

    private static func writePolicy(for policy: FSVolume.SetXattrPolicy) -> XattrWritePolicy {
        switch policy {
        case .mustCreate:  return .mustCreate
        case .mustReplace: return .mustReplace
        default:           return .alwaysSet
        }
    }
}
