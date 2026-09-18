import Foundation
import VaultCore

/// Facade forwarding Keychain helper calls to `VaultCore.KeychainStore`.
enum KeychainHelper {
    static var accessGroup: String { KeychainStore.accessGroup }
    static var serviceName: String { KeychainStore.serviceName }

    @discardableResult
    static func saveCredentialStatus(account: String, data: Data) -> OSStatus {
        KeychainStore.saveCredentialStatus(account: account, data: data)
    }

    @discardableResult
    static func saveCredential(account: String, data: Data) -> Bool {
        KeychainStore.saveCredential(account: account, data: data)
    }

    @discardableResult
    static func deleteCredential(account: String) -> Bool {
        KeychainStore.deleteCredential(account: account)
    }
}
