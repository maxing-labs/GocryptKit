import Foundation
import SwiftUI
import VaultCore

public struct VaultFileItem: Identifiable, Hashable, Sendable {
    public var id: String { relativePath }
    public let name: String
    public let relativePath: String
    public let isDirectory: Bool
    public let mode: UInt32
    public var size: UInt64?
    
    public init(name: String, parentPath: String, mode: UInt32, size: UInt64? = nil) {
        self.name = name
        self.relativePath = parentPath.isEmpty ? name : "\(parentPath)/\(name)"
        self.mode = mode
        self.isDirectory = (mode & UInt32(S_IFMT)) == UInt32(S_IFDIR)
        self.size = size
    }
    
    /// Returns descriptive SF Symbol icon name and tint color.
    public var iconDetails: (symbol: String, color: Color) {
        if isDirectory {
            return ("folder.fill", .blue)
        }
        
        let ext = (name as NSString).pathExtension.lowercased()
        switch ext {
        case "png", "jpg", "jpeg", "heic", "gif", "webp", "bmp", "tiff":
            return ("photo.fill", .teal)
        case "mp4", "mov", "m4v", "mkv", "avi":
            return ("film.fill", .indigo)
        case "mp3", "wav", "m4a", "flac", "aac":
            return ("music.note", .orange)
        case "pdf":
            return ("doc.text.fill", .red)
        case "txt", "md", "markdown", "rtf":
            return ("doc.plaintext.fill", .gray)
        case "swift", "c", "cpp", "h", "go", "py", "js", "ts", "html", "css", "json", "yaml", "yml":
            return ("chevron.left.forwardslash.chevron.right", .purple)
        case "zip", "tar", "gz", "bz2", "7z", "rar":
            return ("doc.zipper", .brown)
        default:
            return ("doc.fill", .secondary)
        }
    }
    
    public var formattedSize: String {
        guard !isDirectory, let size else { return "" }
        return ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
    }
}
