import Foundation
import OSLog
import VaultCore

private let logger = Logger(subsystem: "com.xwei.GocryptKit.iOS", category: "VaultFileOperations")

public enum FileOperationError: LocalizedError {
    case engineNotAvailable
    case cannotReadFile(URL)
    case writeFailed(String)
    case deleteSourceFailed(String)
    
    public var errorDescription: String? {
        switch self {
        case .engineNotAvailable:
            return String(localized: "Vault is not unlocked or engine is unavailable.")
        case .cannotReadFile(let url):
            return String(localized: "Cannot read file to import: \(url.lastPathComponent)")
        case .writeFailed(let msg):
            return String(localized: "Encrypted write failed: \(msg)")
        case .deleteSourceFailed(let msg):
            return String(localized: "File encrypted and imported, but failed to delete original file (sandbox restriction): \(msg)")
        }
    }
}

public struct ImportResult: Sendable {
    public let targetPath: String
    public let bytesWritten: UInt64
    public let sourceDeleted: Bool
    public let deleteWarning: String?
}

public enum VaultFileOperations {
    private static let chunkSize = 64 * 1024 // 64 KiB streamed chunk size
    
    /// Streams and encrypts an imported file, with optional deletion of source file in "move" mode
    public static func importFile(
        sourceURL: URL,
        targetDir: String,
        targetFileName: String? = nil,
        moveSource: Bool = false,
        engine: GocryptfsEngine,
        progress: (@Sendable (Double) -> Void)? = nil
    ) throws -> ImportResult {
        let fileName = targetFileName ?? sourceURL.lastPathComponent
        let targetPath = targetDir.isEmpty ? fileName : "\(targetDir)/\(fileName)"
        
        let isAccessing = sourceURL.startAccessingSecurityScopedResource()
        defer {
            if isAccessing { sourceURL.stopAccessingSecurityScopedResource() }
        }
        
        let fileHandle: FileHandle
        do {
            fileHandle = try FileHandle(forReadingFrom: sourceURL)
        } catch {
            throw FileOperationError.cannotReadFile(sourceURL)
        }
        defer { try? fileHandle.close() }
        
        let totalBytes: UInt64
        if let attrs = try? FileManager.default.attributesOfItem(atPath: sourceURL.path),
           let size = attrs[.size] as? UInt64 {
            totalBytes = size
        } else {
            totalBytes = 0
        }
        
        // Open vault write handle
        let h = try engine.openWrite(targetPath, mode: 0o644)
        var offset: UInt64 = 0
        
        do {
            while true {
                let chunk = try fileHandle.read(upToCount: chunkSize)
                guard let chunk, !chunk.isEmpty else { break }
                
                try chunk.withUnsafeBytes { raw in
                    _ = try engine.write(h, offset: offset, from: raw)
                }
                offset += UInt64(chunk.count)
                if totalBytes > 0 {
                    progress?(min(1.0, Double(offset) / Double(totalBytes)))
                }
            }
            engine.close(h)
        } catch {
            engine.close(h)
            // Clean up partially written file on write failure
            try? engine.remove(targetPath)
            throw FileOperationError.writeFailed(error.localizedDescription)
        }
        
        var sourceDeleted = false
        var deleteWarning: String? = nil
        
        if moveSource {
            do {
                try FileManager.default.removeItem(at: sourceURL)
                sourceDeleted = true
            } catch {
                deleteWarning = String(localized: "File encrypted and imported, but failed to delete source file: \(error.localizedDescription)")
                logger.warning("Failed to delete source file in move mode: \(error.localizedDescription, privacy: .public)")
            }
        }
        
        return ImportResult(
            targetPath: targetPath,
            bytesWritten: offset,
            sourceDeleted: sourceDeleted,
            deleteWarning: deleteWarning
        )
    }
    
    /// Streams decrypted file to a local temporary file for QuickLook or system share sheet
    public static func decryptToTempFile(
        relativePath: String,
        engine: GocryptfsEngine,
        tempDir: URL
    ) throws -> URL {
        let h = try engine.open(relativePath)
        defer { engine.close(h) }
        
        let fileName = (relativePath as NSString).lastPathComponent
        let tempFileURL = tempDir.appendingPathComponent(UUID().uuidString).appendingPathComponent(fileName)
        try FileManager.default.createDirectory(at: tempFileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        
        FileManager.default.createFile(atPath: tempFileURL.path, contents: nil)
        let outHandle = try FileHandle(forWritingTo: tempFileURL)
        defer { try? outHandle.close() }
        
        var offset: UInt64 = 0
        var buffer = [UInt8](repeating: 0, count: chunkSize)
        
        while true {
            let bytesRead = try buffer.withUnsafeMutableBytes { raw in
                try engine.read(h, offset: offset, into: raw)
            }
            if bytesRead <= 0 { break }
            try outHandle.write(contentsOf: buffer.prefix(bytesRead))
            offset += UInt64(bytesRead)
        }
        
        return tempFileURL
    }
    
    /// Recursively deletes a file or directory
    public static func removeRecursively(relativePath: String, engine: GocryptfsEngine) throws {
        // Try deleting as a regular file first
        do {
            try engine.remove(relativePath)
            return
        } catch {
            // Not a regular file or directory error; proceed to directory handling
        }
        
        // Directory: recursively clean up children
        let entries = (try? engine.list(relativePath)) ?? []
        for entry in entries {
            let subPath = relativePath.isEmpty ? entry.name : "\(relativePath)/\(entry.name)"
            try removeRecursively(relativePath: subPath, engine: engine)
        }
        
        // Remove empty directory
        try engine.rmdir(relativePath)
    }
    
    /// Computes plaintext file size directly from ciphertext size without decrypting content
    public static func calculatePlainSize(relativePath: String, engine: GocryptfsEngine) -> UInt64? {
        guard let cipherPath = engine.cipherPath(relativePath) else { return nil }
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: cipherPath),
              let cipherSize = attrs[.size] as? UInt64 else {
            return nil
        }
        return engine.plainSize(cipherSize: cipherSize)
    }
}
