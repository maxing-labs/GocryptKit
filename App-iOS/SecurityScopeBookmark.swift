import Foundation
import OSLog

private let logger = Logger(subsystem: "com.xwei.GocryptKit.iOS", category: "SecurityBookmark")

/// Manages Security-Scoped Bookmarks for external directory access
enum SecurityScopeBookmarkHelper {
    /// Creates a security-scoped bookmark from an external directory URL
    static func createBookmark(for url: URL) throws -> Data {
        let isAccessing = url.startAccessingSecurityScopedResource()
        defer {
            if isAccessing {
                url.stopAccessingSecurityScopedResource()
            }
        }
        
        return try url.bookmarkData(
            options: .minimalBookmark,
            includingResourceValuesForKeys: nil,
            relativeTo: nil
        )
    }
    
    /// Resolves a URL from bookmark data
    /// - Returns: (Resolved URL, whether the bookmark data is stale)
    static func resolveBookmark(data: Data) throws -> (url: URL, isStale: Bool) {
        var isStale = false
        let url = try URL(
            resolvingBookmarkData: data,
            options: .withoutUI,
            relativeTo: nil,
            bookmarkDataIsStale: &isStale
        )
        return (url, isStale)
    }
}

/// Manages the lifecycle of a Security-Scoped Resource automatically
public final class SecurityScopedURL: @unchecked Sendable {
    public let url: URL
    private var isAccessing: Bool = false
    private let lock = NSLock()
    
    public init(url: URL) {
        self.url = url
    }
    
    @discardableResult
    public func startAccessing() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !isAccessing else { return true }
        isAccessing = url.startAccessingSecurityScopedResource()
        if !isAccessing {
            logger.error("Failed to obtain security-scoped resource access: \(self.url.path, privacy: .public)")
        }
        return isAccessing
    }
    
    public func stopAccessing() {
        lock.lock()
        defer { lock.unlock() }
        guard isAccessing else { return }
        url.stopAccessingSecurityScopedResource()
        isAccessing = false
    }
    
    deinit {
        stopAccessing()
    }
}
