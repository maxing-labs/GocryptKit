import SwiftUI
import PhotosUI

struct FileBrowserView: View {
    @State private var viewModel: FileBrowserViewModel
    @State private var showingNewFolderAlert = false
    @State private var newFolderName = ""
    
    @State private var itemToRename: VaultFileItem?
    @State private var renameText = ""
    @State private var itemToDelete: VaultFileItem?
    
    @State private var isImportingFiles = false
    @State private var isMovingFiles = false
    @State private var selectedPhotos: [PhotosPickerItem] = []
    
    init(path: String = "") {
        _viewModel = State(initialValue: FileBrowserViewModel(currentPath: path))
    }
    
    var body: some View {
        Group {
            if viewModel.isLoading && viewModel.items.isEmpty {
                ProgressView("Loading directory...")
            } else if viewModel.filteredAndSortedItems.isEmpty {
                emptyPlaceholderView
            } else {
                fileListView
            }
        }
        .navigationTitle(viewModel.currentDirectoryName)
        .navigationBarTitleDisplayMode(.inline)
        .searchable(text: $viewModel.searchQuery, prompt: "Search files in current folder")
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                sortMenu
                addMenu
            }
            if viewModel.currentPath.isEmpty {
                ToolbarItem(placement: .topBarLeading) {
                    Button(role: .destructive) {
                        VaultSession.shared.lock()
                    } label: {
                        Label("Lock Vault", systemImage: "lock.fill")
                    }
                }
            }
        }
        .safeAreaInset(edge: .top) {
            if let progress = viewModel.importProgress {
                VStack(spacing: 4) {
                    ProgressView(value: progress)
                        .progressViewStyle(.linear)
                    Text("Streaming and encrypting... \(Int(progress * 100))%")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal)
                .padding(.vertical, 6)
                .background(.ultraThinMaterial)
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .animation(.easeInOut(duration: 0.25), value: viewModel.importProgress != nil)
        .onAppear {
            viewModel.refresh()
        }
        .refreshable {
            viewModel.refresh()
        }
        // Alerts and confirmation dialogs
        .alert("New Folder", isPresented: $showingNewFolderAlert) {
            TextField("Folder Name", text: $newFolderName)
            Button("Cancel", role: .cancel) { newFolderName = "" }
            Button("Create") {
                viewModel.createFolder(name: newFolderName)
                newFolderName = ""
            }
        }
        .alert("Rename", isPresented: Binding(get: { itemToRename != nil }, set: { if !$0 { itemToRename = nil } })) {
            TextField("New Name", text: $renameText)
            Button("Cancel", role: .cancel) { itemToRename = nil }
            Button("Save") {
                if let item = itemToRename {
                    viewModel.renameItem(item, to: renameText)
                }
                itemToRename = nil
            }
        }
        .confirmationDialog(
            "Confirm Deletion?",
            isPresented: Binding(get: { itemToDelete != nil }, set: { if !$0 { itemToDelete = nil } }),
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                if let item = itemToDelete {
                    viewModel.deleteItem(item)
                }
                itemToDelete = nil
            }
            Button("Cancel", role: .cancel) { itemToDelete = nil }
        } message: {
            if let item = itemToDelete {
                Text("Are you sure you want to permanently delete \"\(item.name)\" from the vault? This action cannot be undone.")
            }
        }
        .alert("Notice", isPresented: Binding(get: { viewModel.activeMessage != nil }, set: { if !$0 { viewModel.activeMessage = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            if let msg = viewModel.activeMessage {
                Text(msg)
            }
        }
        .alert("Error", isPresented: Binding(get: { viewModel.activeErrorMessage != nil }, set: { if !$0 { viewModel.activeErrorMessage = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            if let err = viewModel.activeErrorMessage {
                Text(err)
            }
        }
        // Document pickers
        .sheet(isPresented: $isImportingFiles) {
            FileImportPicker(allowsMultiple: true) { urls in
                viewModel.importFiles(from: urls, moveSource: false)
            }
        }
        .sheet(isPresented: $isMovingFiles) {
            FileImportPicker(allowsMultiple: true) { urls in
                viewModel.importFiles(from: urls, moveSource: true)
            }
        }
        // QuickLook preview
        .fullScreenCover(item: Binding(get: {
            viewModel.previewFileURL.map { IdentifiableURL(url: $0) }
        }, set: {
            if $0 == nil { viewModel.previewFileURL = nil }
        })) { item in
            QuickLookPreviewController(url: item.url) {
                viewModel.previewFileURL = nil
            }
            .ignoresSafeArea()
        }
        // Share sheet
        .sheet(item: Binding(get: {
            viewModel.shareFileURL.map { IdentifiableURL(url: $0) }
        }, set: {
            if $0 == nil { viewModel.shareFileURL = nil }
        })) { item in
            ActivityView(activityItems: [item.url]) {
                viewModel.shareFileURL = nil
            }
        }
    }
    
    // MARK: - Subviews
    
    private var fileListView: some View {
        List {
            ForEach(viewModel.filteredAndSortedItems) { item in
                if item.isDirectory {
                    NavigationLink(destination: FileBrowserView(path: item.relativePath)) {
                        rowContent(for: item)
                    }
                    .contextMenu {
                        contextMenuContent(for: item)
                    }
                    .swipeActions(edge: .trailing) {
                        deleteSwipeAction(for: item)
                    }
                } else {
                    Button {
                        viewModel.previewItem(item)
                    } label: {
                        rowContent(for: item)
                    }
                    .buttonStyle(.plain)
                    .contextMenu {
                        contextMenuContent(for: item)
                    }
                    .swipeActions(edge: .trailing) {
                        deleteSwipeAction(for: item)
                    }
                    .swipeActions(edge: .leading) {
                        Button {
                            viewModel.shareItem(item)
                        } label: {
                            Label("Share", systemImage: "square.and.arrow.up")
                        }
                        .tint(.blue)
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
    }
    
    private func rowContent(for item: VaultFileItem) -> some View {
        HStack(spacing: 12) {
            Image(systemName: item.iconDetails.symbol)
                .font(.title2)
                .foregroundStyle(item.iconDetails.color)
                .frame(width: 32)
            
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name)
                    .font(.body)
                    .lineLimit(1)
                
                if !item.isDirectory {
                    Text(item.formattedSize)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            
            Spacer()
        }
        .contentShape(Rectangle())
        .padding(.vertical, 4)
    }
    
    @ViewBuilder
    private func contextMenuContent(for item: VaultFileItem) -> some View {
        if !item.isDirectory {
            Button {
                viewModel.shareItem(item)
            } label: {
                Label("Export and Share", systemImage: "square.and.arrow.up")
            }
        }
        
        Button {
            itemToRename = item
            renameText = item.name
        } label: {
            Label("Rename", systemImage: "pencil")
        }
        
        Divider()
        
        Button(role: .destructive) {
            itemToDelete = item
        } label: {
            Label("Delete", systemImage: "trash")
        }
    }
    
    private func deleteSwipeAction(for item: VaultFileItem) -> some View {
        Button(role: .destructive) {
            itemToDelete = item
        } label: {
            Label("Delete", systemImage: "trash")
        }
    }
    
    private var emptyPlaceholderView: some View {
        ContentUnavailableView {
            Label(
                viewModel.searchQuery.isEmpty ? "Folder is empty" : "No matching files",
                systemImage: viewModel.searchQuery.isEmpty ? "folder" : "magnifyingglass"
            )
        } description: {
            Text(viewModel.searchQuery.isEmpty ? "Tap \"+\" in the top right to import or move external files" : "No items matching \"\(viewModel.searchQuery)\" were found")
        } actions: {
            if viewModel.searchQuery.isEmpty {
                Button {
                    isImportingFiles = true
                } label: {
                    Label("Import Files", systemImage: "square.and.arrow.down")
                }
                .buttonStyle(.borderedProminent)
            }
        }
    }
    
    private var sortMenu: some View {
        Menu {
            Picker("Sort By", selection: $viewModel.sortOption) {
                ForEach(FileSortOption.allCases) { opt in
                    Text(opt.localizedTitle).tag(opt)
                }
            }
            
            Divider()
            
            Toggle("Ascending", isOn: $viewModel.sortAscending)
        } label: {
            Label("Sort", systemImage: "arrow.up.arrow.down")
        }
    }
    
    private var addMenu: some View {
        Menu {
            Button {
                newFolderName = ""
                showingNewFolderAlert = true
            } label: {
                Label("New Folder", systemImage: "folder.badge.plus")
            }
            
            Divider()
            
            Button {
                isImportingFiles = true
            } label: {
                Label("Import from Files (Keep Original)", systemImage: "square.and.arrow.down")
            }
            
            Button {
                isMovingFiles = true
            } label: {
                Label("Move from Files (Delete Original)", systemImage: "arrow.right.doc.on.clipboard")
            }
            
            PhotosPicker(
                selection: $selectedPhotos,
                matching: .any(of: [.images, .videos]),
                photoLibrary: .shared()
            ) {
                Label("Import Photos/Videos from Library", systemImage: "photo.on.rectangle.angled")
            }
        } label: {
            Image(systemName: "plus")
        }
        .onChange(of: selectedPhotos) { _, newItems in
            if !newItems.isEmpty {
                viewModel.importPhotos(items: newItems)
                selectedPhotos = []
            }
        }
    }
}

/// Wraps URL with an identifier for sheet/fullScreenCover bindings
struct IdentifiableURL: Identifiable {
    let id = UUID()
    let url: URL
}
