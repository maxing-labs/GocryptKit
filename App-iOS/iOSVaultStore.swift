import Foundation
import Observation
import OSLog
import VaultCore

private let logger = Logger(subsystem: "com.xwei.GocryptKit.iOS", category: "iOSVaultStore")

@MainActor
@Observable
final class iOSVaultStore {
    private(set) var vaults: [iOSVault] = []
    private let saveURL: URL
    
    init() {
        let fileManager = FileManager.default
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
        
        try? fileManager.createDirectory(at: appSupport, withIntermediateDirectories: true)
        self.saveURL = appSupport.appendingPathComponent("gocryptfs_vaults.json")
        load()
    }
    
    private func load() {
        guard FileManager.default.fileExists(atPath: saveURL.path) else { return }
        do {
            let data = try Data(contentsOf: saveURL)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            vaults = try decoder.decode([iOSVault].self, from: data)
            vaults.sort { $0.lastAccessedAt > $1.lastAccessedAt }
        } catch {
            logger.error("Failed to load vault list: \(error.localizedDescription, privacy: .public)")
        }
    }
    
    private func save() {
        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = .prettyPrinted
            let data = try encoder.encode(vaults)
            try data.write(to: saveURL, options: [.atomic])
        } catch {
            logger.error("Failed to save vault list: \(error.localizedDescription, privacy: .public)")
        }
    }
    
    // MARK: - Operations
    
    @discardableResult
    func addVault(from url: URL, name: String? = nil) throws -> iOSVault {
        let isAccessing = url.startAccessingSecurityScopedResource()
        defer {
            if isAccessing { url.stopAccessingSecurityScopedResource() }
        }
        
        let confURL = url.appendingPathComponent("gocryptfs.conf")
        guard FileManager.default.fileExists(atPath: confURL.path) else {
            throw VaultRegistryError.notAVault(url.lastPathComponent)
        }
        
        let bookmark = try url.bookmarkData(
            options: .minimalBookmark,
            includingResourceValuesForKeys: nil,
            relativeTo: nil
        )
        
        let finalName = name?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
            ? name!
            : url.lastPathComponent
        
        let vault = iOSVault(
            name: finalName,
            bookmarkData: bookmark,
            createdAt: Date(),
            lastAccessedAt: Date()
        )
        
        // Deduplication: if an entry with the same name exists, replace it
        vaults.removeAll { $0.name == finalName }
        vaults.insert(vault, at: 0)
        save()
        return vault
    }
    
    @discardableResult
    func addCreatedVault(url: URL, name: String, bookmark: Data) -> iOSVault {
        let vault = iOSVault(
            name: name,
            bookmarkData: bookmark,
            createdAt: Date(),
            lastAccessedAt: Date()
        )
        vaults.removeAll { $0.name == name }
        vaults.insert(vault, at: 0)
        save()
        return vault
    }
    
    func remove(id: UUID) {
        vaults.removeAll { $0.id == id }
        save()
    }
    
    func rename(id: UUID, newName: String) {
        let trimmed = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        if let idx = vaults.firstIndex(where: { $0.id == id }) {
            vaults[idx].name = trimmed
            save()
        }
    }
    
    func touch(id: UUID) {
        if let idx = vaults.firstIndex(where: { $0.id == id }) {
            vaults[idx].lastAccessedAt = Date()
            vaults.sort { $0.lastAccessedAt > $1.lastAccessedAt }
            save()
        }
    }
    
    func updateBookmark(id: UUID, newBookmark: Data) {
        if let idx = vaults.firstIndex(where: { $0.id == id }) {
            vaults[idx].bookmarkData = newBookmark
            save()
        }
    }
}
