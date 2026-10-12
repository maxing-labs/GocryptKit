import Foundation
import Security
import OSLog

private let logger = Logger(subsystem: "com.xwei.GocryptKit", category: "KeychainStore")

/// Unified Keychain operations for GocryptKit host apps and extensions.
/// Centralizes query construction, error logging, and access-group management.
public enum KeychainStore {
    public static var accessGroup: String { KeychainConfig.accessGroup }
    public static var serviceName: String { KeychainConfig.serviceName }

    /// Saves a credential into the shared Data Protection Keychain.
    /// Returns errSecSuccess or an OSStatus error code.
    @discardableResult
    public static func saveCredentialStatus(account: String, data: Data) -> OSStatus {
        var deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
        ]
        if !accessGroup.isEmpty {
            deleteQuery[kSecAttrAccessGroup as String] = accessGroup
            deleteQuery[kSecUseDataProtectionKeychain as String] = true
        }
        SecItemDelete(deleteQuery as CFDictionary)

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        if !accessGroup.isEmpty {
            query[kSecAttrAccessGroup as String] = accessGroup
            query[kSecUseDataProtectionKeychain as String] = true
        }

        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecSuccess {
            logger.info("Saved credential to Keychain for account: \(account, privacy: .private)")
        } else {
            logger.error("Failed to save credential to Keychain: status \(status, privacy: .public)")
        }
        return status
    }

    /// Convenience wrapper returning Bool for `saveCredentialStatus`.
    @discardableResult
    public static func saveCredential(account: String, data: Data) -> Bool {
        saveCredentialStatus(account: account, data: data) == errSecSuccess
    }

    /// Loads credential data from the shared Data Protection Keychain.
    public static func loadCredential(account: String) -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        if !accessGroup.isEmpty {
            query[kSecAttrAccessGroup as String] = accessGroup
            query[kSecUseDataProtectionKeychain as String] = true
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let data = item as? Data {
            logger.info("Credential found in Keychain")
            return data
        } else {
            logger.error("No credential in Keychain for account \(account, privacy: .private), status=\(status, privacy: .public)")
            return nil
        }
    }

    /// One stored item of this service: a credential or a mount context.
    public struct StoredItem: Equatable, Sendable {
        public let account: String
        /// When the item was written. Saving replaces the item, so this is its age.
        public let savedAt: Date?

        public init(account: String, savedAt: Date?) {
            self.account = account
            self.savedAt = savedAt
        }
    }

    /// Every item stored under this service, including ones for vaults that are
    /// not registered in the app (CLI mounts). Values are not read.
    public static func storedItems() -> [StoredItem] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        if !accessGroup.isEmpty {
            query[kSecAttrAccessGroup as String] = accessGroup
            query[kSecUseDataProtectionKeychain as String] = true
        }
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [[String: Any]] else {
            return []
        }
        return items.compactMap { attributes in
            guard let account = attributes[kSecAttrAccount as String] as? String else { return nil }
            let savedAt = (attributes[kSecAttrModificationDate as String] ?? attributes[kSecAttrCreationDate as String]) as? Date
            return StoredItem(account: account, savedAt: savedAt)
        }
    }

    /// Deletes the credential for the given account from the shared Keychain.
    @discardableResult
    public static func deleteCredential(account: String) -> Bool {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
        ]
        if !accessGroup.isEmpty {
            query[kSecAttrAccessGroup as String] = accessGroup
            query[kSecUseDataProtectionKeychain as String] = true
        }
        let status = SecItemDelete(query as CFDictionary)
        logger.debug("Deleted credential from Keychain for account: \(account, privacy: .private), status=\(status)")
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
