import Foundation
import SwiftUI
import PhotosUI
import Observation
import OSLog
import VaultCore

private let logger = Logger(subsystem: "com.xwei.GocryptKit.iOS", category: "FileBrowserViewModel")

public enum FileSortOption: String, CaseIterable, Identifiable {
    case name
    case type
    case size
    
    public var id: String { rawValue }
    
    public var localizedTitle: LocalizedStringKey {
        switch self {
        case .name: return "Name"
        case .type: return "Type"
        case .size: return "Size"
        }
    }
}

@MainActor
@Observable
final class FileBrowserViewModel {
    let currentPath: String
    private(set) var items: [VaultFileItem] = []
    private(set) var isLoading: Bool = false
    
    var searchQuery: String = ""
    var sortOption: FileSortOption = .name
    var sortAscending: Bool = true
    
    // Progress and status
    var importProgress: Double? = nil
    var activeMessage: String? = nil
    var activeErrorMessage: String? = nil
    
    // Preview and share target URLs
    var previewFileURL: URL? = nil
    var shareFileURL: URL? = nil
    
    init(currentPath: String = "") {
        self.currentPath = currentPath
    }
    
    var currentDirectoryName: String {
        if currentPath.isEmpty {
            return VaultSession.shared.currentVault?.name ?? String(localized: "Encrypted Vault")
        }
        return (currentPath as NSString).lastPathComponent
    }
    
    var filteredAndSortedItems: [VaultFileItem] {
        var result = items
        if !searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            result = result.filter { $0.name.localizedCaseInsensitiveContains(searchQuery) }
        }
        
        result.sort { a, b in
            // Directories always sort before regular files
            if a.isDirectory != b.isDirectory {
                return a.isDirectory && !b.isDirectory
            }
            
            switch sortOption {
            case .name:
                let comp = a.name.localizedStandardCompare(b.name)
                return sortAscending ? (comp == .orderedAscending) : (comp == .orderedDescending)
            case .type:
                let extA = (a.name as NSString).pathExtension.lowercased()
                let extB = (b.name as NSString).pathExtension.lowercased()
                if extA != extB {
                    return sortAscending ? (extA < extB) : (extA > extB)
                }
                return a.name.localizedStandardCompare(b.name) == .orderedAscending
            case .size:
                let sA = a.size ?? 0
                let sB = b.size ?? 0
                if sA != sB {
                    return sortAscending ? (sA < sB) : (sA > sB)
                }
                return a.name.localizedStandardCompare(b.name) == .orderedAscending
            }
        }
        return result
    }
    
    func refresh() {
        guard let engine = VaultSession.shared.engine else { return }
        isLoading = true
        
        Task {
            do {
                let path = self.currentPath
                let (entries, itemsWithSize) = try await Task.detached(priority: .userInitiated) { () -> ([VaultCore.DirEntry], [VaultFileItem]) in
                    let entries = try engine.list(path)
                    let items = entries.map { entry in
                        let item = VaultFileItem(
                            name: entry.name,
                            parentPath: path,
                            mode: entry.mode
                        )
                        var mutableItem = item
                        if !item.isDirectory {
                            mutableItem.size = VaultFileOperations.calculatePlainSize(
                                relativePath: item.relativePath,
                                engine: engine
                            )
                        }
                        return mutableItem
                    }
                    return (entries, items)
                }.value
                
                self.items = itemsWithSize
                self.isLoading = false
            } catch {
                self.isLoading = false
                self.activeErrorMessage = String(localized: "Failed to read directory: \(error.localizedDescription)")
            }
        }
    }
    
    // MARK: - File Operations
    
    func createFolder(name: String) {
        guard let engine = VaultSession.shared.engine else { return }
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        
        let newPath = currentPath.isEmpty ? trimmed : "\(currentPath)/\(trimmed)"
        do {
            try engine.mkdir(newPath, mode: 0o755)
            refresh()
        } catch {
            activeErrorMessage = String(localized: "Failed to create folder: \(error.localizedDescription)")
        }
    }
    
    func renameItem(_ item: VaultFileItem, to newName: String) {
        guard let engine = VaultSession.shared.engine else { return }
        let trimmed = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != item.name else { return }
        
        let newPath = currentPath.isEmpty ? trimmed : "\(currentPath)/\(trimmed)"
        do {
            try engine.rename(from: item.relativePath, to: newPath)
            refresh()
        } catch {
            activeErrorMessage = String(localized: "Failed to rename: \(error.localizedDescription)")
        }
    }
    
    func deleteItem(_ item: VaultFileItem) {
        guard let engine = VaultSession.shared.engine else { return }
        do {
            try VaultFileOperations.removeRecursively(relativePath: item.relativePath, engine: engine)
            refresh()
        } catch {
            activeErrorMessage = String(localized: "Failed to delete: \(error.localizedDescription)")
        }
    }
    
    // MARK: - Import and Move
    
    func importFiles(from urls: [URL], moveSource: Bool) {
        guard let engine = VaultSession.shared.engine else { return }
        guard !urls.isEmpty else { return }
        
        withAnimation(.easeInOut(duration: 0.2)) {
            self.importProgress = 0.0
        }
        
        Task {
            var warnings: [String] = []
            let total = urls.count
            let path = self.currentPath
            
            defer {
                // Ensure progress bar is cleared on error or cancellation
                if self.importProgress != nil {
                    withAnimation(.easeOut(duration: 0.25)) {
                        self.importProgress = nil
                    }
                }
            }
            
            for (index, url) in urls.enumerated() {
                do {
                    let res = try await Task.detached(priority: .userInitiated) { () -> ImportResult in
                        try VaultFileOperations.importFile(
                            sourceURL: url,
                            targetDir: path,
                            moveSource: moveSource,
                            engine: engine
                        ) { fraction in
                            let overall = (Double(index) + fraction) / Double(total)
                            Task { @MainActor [weak self] in
                                self?.importProgress = overall
                            }
                        }
                    }.value
                    
                    if let warn = res.deleteWarning {
                        warnings.append(warn)
                    }
                } catch {
                    warnings.append("\(url.lastPathComponent): \(error.localizedDescription)")
                }
            }
            
            // Import complete: reach 100%, hold for 0.5s, then fade out
            self.importProgress = 1.0
            try? await Task.sleep(for: .milliseconds(500))
            withAnimation(.easeOut(duration: 0.3)) {
                self.importProgress = nil
            }
            
            self.refresh()
            
            if !warnings.isEmpty {
                self.activeMessage = warnings.joined(separator: "\n")
            }
        }
    }
    
    func importPhotos(items photoItems: [PhotosPickerItem], moveSource: Bool = false) {
        guard let engine = VaultSession.shared.engine else { return }
        guard !photoItems.isEmpty else { return }
        
        withAnimation(.easeInOut(duration: 0.2)) {
            self.importProgress = 0.0
        }
        
        Task {
            let total = photoItems.count
            let path = self.currentPath
            
            defer {
                if self.importProgress != nil {
                    withAnimation(.easeOut(duration: 0.25)) {
                        self.importProgress = nil
                    }
                }
            }
            
            for (index, item) in photoItems.enumerated() {
                do {
                    if let data = try await item.loadTransferable(type: Data.self) {
                        let filename: String
                        if let contentType = item.supportedContentTypes.first,
                           let ext = contentType.preferredFilenameExtension {
                            filename = "IMG_\(Int(Date().timeIntervalSince1970))_\(index + 1).\(ext)"
                        } else {
                            filename = "IMG_\(Int(Date().timeIntervalSince1970))_\(index + 1).jpg"
                        }
                        
                        let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent(filename)
                        try data.write(to: tempURL)
                        
                        try await Task.detached(priority: .userInitiated) {
                            _ = try VaultFileOperations.importFile(
                                sourceURL: tempURL,
                                targetDir: path,
                                targetFileName: filename,
                                moveSource: true,
                                engine: engine
                            )
                        }.value
                        
                        let overall = Double(index + 1) / Double(total)
                        self.importProgress = overall
                    }
                } catch {
                    logger.error("Failed to import photo: \(error.localizedDescription, privacy: .public)")
                }
            }
            
            // Complete: hold for 0.5s, then smoothly fade out
            self.importProgress = 1.0
            try? await Task.sleep(for: .milliseconds(500))
            withAnimation(.easeOut(duration: 0.3)) {
                self.importProgress = nil
            }
            
            self.refresh()
        }
    }
    
    // MARK: - Preview and Share
    
    func previewItem(_ item: VaultFileItem) {
        guard !item.isDirectory, let engine = VaultSession.shared.engine else { return }
        let tempDir = VaultSession.shared.getPreviewDirectory()
        
        Task {
            do {
                let fileURL = try await Task.detached(priority: .userInitiated) {
                    try VaultFileOperations.decryptToTempFile(
                        relativePath: item.relativePath,
                        engine: engine,
                        tempDir: tempDir
                    )
                }.value
                self.previewFileURL = fileURL
            } catch {
                self.activeErrorMessage = String(localized: "Failed to decrypt for preview: \(error.localizedDescription)")
            }
        }
    }
    
    func shareItem(_ item: VaultFileItem) {
        guard !item.isDirectory, let engine = VaultSession.shared.engine else { return }
        let tempDir = VaultSession.shared.getPreviewDirectory()
        
        Task {
            do {
                let fileURL = try await Task.detached(priority: .userInitiated) {
                    try VaultFileOperations.decryptToTempFile(
                        relativePath: item.relativePath,
                        engine: engine,
                        tempDir: tempDir
                    )
                }.value
                self.shareFileURL = fileURL
            } catch {
                self.activeErrorMessage = String(localized: "Failed to decrypt for export: \(error.localizedDescription)")
            }
        }
    }
}
