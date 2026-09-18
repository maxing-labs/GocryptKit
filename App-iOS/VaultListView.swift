import SwiftUI
import VaultCore

struct VaultListView: View {
    @State private var store = iOSVaultStore()
    @State private var session = VaultSession.shared
    
    @State private var isShowingCreateSheet = false
    @State private var isShowingFolderPicker = false
    @State private var vaultToUnlock: iOSVault?
    
    @State private var vaultToRename: iOSVault?
    @State private var renameText = ""
    @State private var vaultToDelete: iOSVault?
    
    @State private var errorMessage: String?
    
    var body: some View {
        Group {
            if session.isUnlocked {
                NavigationStack {
                    FileBrowserView(path: "")
                }
            } else {
                vaultsNavigationList
            }
        }
    }
    
    private var vaultsNavigationList: some View {
        NavigationStack {
            Group {
                if store.vaults.isEmpty {
                    emptyStateView
                } else {
                    List {
                        Section("All Vaults") {
                            ForEach(store.vaults) { vault in
                                Button {
                                    vaultToUnlock = vault
                                } label: {
                                    vaultRow(for: vault)
                                }
                                .buttonStyle(.plain)
                                .contextMenu {
                                    Button {
                                        vaultToRename = vault
                                        renameText = vault.name
                                    } label: {
                                        Label("Rename", systemImage: "pencil")
                                    }
                                    Divider()
                                    Button(role: .destructive) {
                                        vaultToDelete = vault
                                    } label: {
                                        Label("Remove from List", systemImage: "trash")
                                    }
                                }
                                .swipeActions(edge: .trailing) {
                                    Button(role: .destructive) {
                                        vaultToDelete = vault
                                    } label: {
                                        Label("Remove", systemImage: "trash")
                                    }
                                    Button {
                                        vaultToRename = vault
                                        renameText = vault.name
                                    } label: {
                                        Label("Rename", systemImage: "pencil")
                                    }
                                    .tint(.orange)
                                }
                            }
                        }
                    }
                    .listStyle(.insetGrouped)
                }
            }
            .navigationTitle("GocryptKit")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button {
                            isShowingFolderPicker = true
                        } label: {
                            Label("Open Existing Vault", systemImage: "folder.badge.gearshape")
                        }
                        
                        Button {
                            isShowingCreateSheet = true
                        } label: {
                            Label("New Encrypted Vault", systemImage: "plus.circle")
                        }
                    } label: {
                        Image(systemName: "plus")
                    }
                }
            }
            .sheet(item: $vaultToUnlock) { vault in
                UnlockVaultSheet(vault: vault) {
                    store.touch(id: vault.id)
                }
            }
            .sheet(isPresented: $isShowingCreateSheet) {
                CreateVaultSheet(store: store) { newVault in
                    vaultToUnlock = newVault
                }
            }
            .sheet(isPresented: $isShowingFolderPicker) {
                FolderPicker { pickedURL in
                    do {
                        let newVault = try store.addVault(from: pickedURL)
                        vaultToUnlock = newVault
                    } catch {
                        errorMessage = error.localizedDescription
                    }
                }
            }
            .alert("Rename Vault", isPresented: Binding(get: { vaultToRename != nil }, set: { if !$0 { vaultToRename = nil } })) {
                TextField("Vault Name", text: $renameText)
                Button("Cancel", role: .cancel) { vaultToRename = nil }
                Button("Save") {
                    if let vault = vaultToRename {
                        store.rename(id: vault.id, newName: renameText)
                    }
                    vaultToRename = nil
                }
            }
            .confirmationDialog(
                "Confirm Removal?",
                isPresented: Binding(get: { vaultToDelete != nil }, set: { if !$0 { vaultToDelete = nil } }),
                titleVisibility: .visible
            ) {
                Button("Remove from List", role: .destructive) {
                    if let vault = vaultToDelete {
                        store.remove(id: vault.id)
                    }
                    vaultToDelete = nil
                }
                Button("Cancel", role: .cancel) { vaultToDelete = nil }
            } message: {
                Text("This only removes the record from this app's list. Encrypted data on disk will not be deleted.")
            }
            .alert("Error", isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })) {
                Button("OK", role: .cancel) {}
            } message: {
                if let err = errorMessage {
                    Text(err)
                }
            }
        }
    }
    
    private func vaultRow(for vault: iOSVault) -> some View {
        HStack(spacing: 14) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 28))
                .foregroundStyle(.blue)
            
            VStack(alignment: .leading, spacing: 3) {
                Text(vault.name)
                    .font(.headline)
                    .foregroundStyle(.primary)
                Text("Tap to unlock with password")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
            
            Image(systemName: "chevron.right")
                .font(.footnote)
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }
    
    private var emptyStateView: some View {
        ContentUnavailableView {
            Label("No Vaults", systemImage: "lock.trianglebadge.exclamationmark")
        } description: {
            Text("Open an existing gocryptfs directory or create a new encrypted vault.")
        } actions: {
            HStack(spacing: 12) {
                Button {
                    isShowingFolderPicker = true
                } label: {
                    Label("Open Existing Vault", systemImage: "folder.badge.gearshape")
                }
                .buttonStyle(.bordered)
                
                Button {
                    isShowingCreateSheet = true
                } label: {
                    Label("New Encrypted Vault", systemImage: "plus")
                }
                .buttonStyle(.borderedProminent)
            }
        }
    }
}
