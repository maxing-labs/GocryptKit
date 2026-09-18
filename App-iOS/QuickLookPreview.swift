import SwiftUI
import QuickLook

/// SwiftUI wrapper for QLPreviewController
struct QuickLookPreviewController: UIViewControllerRepresentable {
    let url: URL
    let onDismiss: () -> Void
    
    func makeUIViewController(context: Context) -> UINavigationController {
        let preview = QLPreviewController()
        preview.dataSource = context.coordinator
        preview.delegate = context.coordinator
        
        let nav = UINavigationController(rootViewController: preview)
        let doneButton = UIBarButtonItem(
            systemItem: .done,
            primaryAction: UIAction { _ in
                onDismiss()
            }
        )
        preview.navigationItem.rightBarButtonItem = doneButton
        return nav
    }
    
    func updateUIViewController(_ uiViewController: UINavigationController, context: Context) {}
    
    func makeCoordinator() -> Coordinator {
        Coordinator(parent: self)
    }
    
    final class Coordinator: NSObject, QLPreviewControllerDataSource, QLPreviewControllerDelegate {
        let parent: QuickLookPreviewController
        
        init(parent: QuickLookPreviewController) {
            self.parent = parent
        }
        
        nonisolated func numberOfPreviewItems(in controller: QLPreviewController) -> Int {
            1
        }
        
        nonisolated func previewController(_ controller: QLPreviewController, previewItemAt index: Int) -> any QLPreviewItem {
            parent.url as NSURL
        }
        
        nonisolated func previewControllerDidDismiss(_ controller: QLPreviewController) {
            Task { @MainActor in
                self.parent.onDismiss()
            }
        }
    }
}

/// SwiftUI wrapper for UIActivityViewController (system share sheet)
struct ActivityView: UIViewControllerRepresentable {
    let activityItems: [Any]
    let applicationActivities: [UIActivity]? = nil
    var onCompletion: (() -> Void)? = nil
    
    func makeUIViewController(context: Context) -> UIActivityViewController {
        let controller = UIActivityViewController(
            activityItems: activityItems,
            applicationActivities: applicationActivities
        )
        controller.completionWithItemsHandler = { _, _, _, _ in
            onCompletion?()
        }
        return controller
    }
    
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
