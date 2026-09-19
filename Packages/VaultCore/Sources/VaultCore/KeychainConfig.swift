import Foundation

/// Unified Keychain configuration for host apps and extensions.
public enum KeychainConfig {
    public static let defaultServiceName = "com.xwei.GocryptfsKit"
    public static let defaultAccessGroup = "QBFSP2CHNW.com.xwei.GocryptfsKit"

    /// Dynamically resolves the keychain access group:
    /// 1. Environment variable `GOCRYPTFSKIT_KEYCHAIN_ACCESS_GROUP` (useful for testing/CI)
    /// 2. Info.plist key `KeychainAccessGroup`
    /// 3. Default fallback `QBFSP2CHNW.com.xwei.GocryptfsKit`
    public static var accessGroup: String {
        #if DEBUG
        if let env = ProcessInfo.processInfo.environment["GOCRYPTFSKIT_KEYCHAIN_ACCESS_GROUP"] {
            return (env == "NONE" || env.isEmpty) ? "" : env
        }
        #endif
        if let plist = Bundle.main.object(forInfoDictionaryKey: "KeychainAccessGroup") as? String, !plist.isEmpty {
            return plist
        }
        return defaultAccessGroup
    }

    /// Dynamically resolves the keychain service name:
    /// 1. Environment variable `GOCRYPTFSKIT_KEYCHAIN_SERVICE_NAME` (DEBUG only)
    /// 2. Info.plist key `KeychainServiceName`
    /// 3. Default fallback `com.xwei.GocryptfsKit`
    public static var serviceName: String {
        #if DEBUG
        if let env = ProcessInfo.processInfo.environment["GOCRYPTFSKIT_KEYCHAIN_SERVICE_NAME"], !env.isEmpty {
            return env
        }
        #endif
        if let plist = Bundle.main.object(forInfoDictionaryKey: "KeychainServiceName") as? String, !plist.isEmpty {
            return plist
        }
        return defaultServiceName
    }
}
