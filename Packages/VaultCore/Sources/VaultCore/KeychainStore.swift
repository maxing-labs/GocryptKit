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
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecUseDataProtectionKeychain as String: true
        ]

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
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

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

    /// Deletes the credential for the given account from the shared Keychain.
    @discardableResult
    public static func deleteCredential(account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true
        ]
        let status = SecItemDelete(query as CFDictionary)
        logger.debug("Deleted credential from Keychain for account: \(account, privacy: .private), status=\(status)")
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
