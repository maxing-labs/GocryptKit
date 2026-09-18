import Foundation
import Observation
import OSLog
import VaultCore

private let logger = Logger(subsystem: "com.xwei.GocryptKit.iOS", category: "VaultSession")

@MainActor
@Observable
final class VaultSession {
    static let shared = VaultSession()
    
    private(set) var currentVault: iOSVault?
    private(set) var engine: GocryptfsEngine?
    private(set) var scopedURL: SecurityScopedURL?
    private(set) var isUnlocked: Bool = false
    
    private let previewCacheDir: URL
    
    init() {
        let tmp = FileManager.default.temporaryDirectory
        self.previewCacheDir = tmp.appendingPathComponent("vault_previews", isDirectory: true)
        try? FileManager.default.createDirectory(at: previewCacheDir, withIntermediateDirectories: true)
    }
    
    func unlock(vault: iOSVault, password: String) throws {
        lock()
        
        var isStale = false
        let url = try URL(
            resolvingBookmarkData: vault.bookmarkData,
            options: .withoutUI,
            relativeTo: nil,
            bookmarkDataIsStale: &isStale
        )
        
        let scoped = SecurityScopedURL(url: url)
        guard scoped.startAccessing() else {
            throw VaultError.invalidCipherDir
        }
        
        do {
            let engine = try GocryptfsEngine(cipherDir: url, credential: .password(password))
            self.currentVault = vault
            self.engine = engine
            self.scopedURL = scoped
            self.isUnlocked = true
            logger.info("Vault '\(vault.name, privacy: .public)' successfully unlocked")
        } catch {
            scoped.stopAccessing()
            logger.error("Unlock failed: \(error.localizedDescription, privacy: .public)")
            throw error
        }
    }
    
    func lock() {
        if let engine {
            engine.shutdown()
            self.engine = nil
        }
        if let scopedURL {
            scopedURL.stopAccessing()
            self.scopedURL = nil
        }
        self.currentVault = nil
        self.isUnlocked = false
        cleanPreviewCache()
        logger.info("Vault safely locked and decrypted cache purged")
    }
    
    func cleanPreviewCache() {
        try? FileManager.default.removeItem(at: previewCacheDir)
        try? FileManager.default.createDirectory(at: previewCacheDir, withIntermediateDirectories: true)
    }
    
    /// Retrieves the decrypted preview cache directory
    func getPreviewDirectory() -> URL {
        try? FileManager.default.createDirectory(at: previewCacheDir, withIntermediateDirectories: true)
        return previewCacheDir
    }
}
