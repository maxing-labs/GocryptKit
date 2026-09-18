import Foundation
import VaultCore

/// Facade forwarding Keychain read/delete calls to `VaultCore.KeychainStore`.
enum KeychainReader {
    static var accessGroup: String { KeychainStore.accessGroup }
    static var serviceName: String { KeychainStore.serviceName }

    static func loadCredential(account: String) -> Data? {
        KeychainStore.loadCredential(account: account)
    }

    @discardableResult
    static func deleteCredential(account: String) -> Bool {
        KeychainStore.deleteCredential(account: account)
    }
}
