import Foundation

/// Vault data model registered on iOS.
public struct iOSVault: Identifiable, Codable, Hashable, Sendable {
    public let id: UUID
    public var name: String
    public var bookmarkData: Data
    public var createdAt: Date
    public var lastAccessedAt: Date
    
    public init(
        id: UUID = UUID(),
        name: String,
        bookmarkData: Data,
        createdAt: Date = Date(),
        lastAccessedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.bookmarkData = bookmarkData
        self.createdAt = createdAt
        self.lastAccessedAt = lastAccessedAt
    }
}
