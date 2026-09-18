import SwiftUI
import UniformTypeIdentifiers

/// Folder picker for selecting external directories (for opening existing vaults or targeting new vaults)
struct FolderPicker: UIViewControllerRepresentable {
    let onPick: (URL) -> Void
    var onCancel: (() -> Void)? = nil
    
    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.folder], asCopy: false)
        picker.allowsMultipleSelection = false
        picker.delegate = context.coordinator
        return picker
    }
    
    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}
    
    func makeCoordinator() -> Coordinator {
        Coordinator(parent: self)
    }
    
    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let parent: FolderPicker
        
        init(parent: FolderPicker) {
            self.parent = parent
        }
        
        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            guard let url = urls.first else { return }
            parent.onPick(url)
        }
        
        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
            parent.onCancel?()
        }
    }
}

/// File picker for importing external files (supports multiple selection)
struct FileImportPicker: UIViewControllerRepresentable {
    let allowsMultiple: Bool
    let onPick: ([URL]) -> Void
    var onCancel: (() -> Void)? = nil
    
    init(allowsMultiple: Bool = true, onPick: @escaping ([URL]) -> Void, onCancel: (() -> Void)? = nil) {
        self.allowsMultiple = allowsMultiple
        self.onPick = onPick
        self.onCancel = onCancel
    }
    
    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.item], asCopy: false)
        picker.allowsMultipleSelection = allowsMultiple
        picker.delegate = context.coordinator
        return picker
    }
    
    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}
    
    func makeCoordinator() -> Coordinator {
        Coordinator(parent: self)
    }
    
    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let parent: FileImportPicker
        
        init(parent: FileImportPicker) {
            self.parent = parent
        }
        
        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            parent.onPick(urls)
        }
        
        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
            parent.onCancel?()
        }
    }
}
