import SwiftUI
import VaultCore

struct CreateVaultSheet: View {
    @Environment(\.dismiss) private var dismiss
    let store: iOSVaultStore
    let onCreated: (iOSVault) -> Void
    
    @State private var vaultName = ""
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var isShowingPassword = false
    
    @State private var selectedFolderURL: URL?
    @State private var isSelectingFolder = false
    @State private var useLocalSandbox = false
    
    @State private var isCreating = false
    @State private var errorMessage: String?
    
    private var passwordStrength: PasswordStrength {
        PasswordStrength.evaluate(password)
    }
    
    private var canCreate: Bool {
        !vaultName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
        passwordStrength > .tooShort &&
        password == confirmPassword &&
        (selectedFolderURL != nil || useLocalSandbox) &&
        !isCreating
    }
    
    var body: some View {
        NavigationStack {
            Form {
                Section("Vault Information") {
                    TextField("Vault Name (e.g. Secret Documents)", text: $vaultName)
                }
                
                Section("Storage Location") {
                    Toggle("Store in App Local Sandbox", isOn: $useLocalSandbox)
                    
                    if !useLocalSandbox {
                        Button {
                            isSelectingFolder = true
                        } label: {
                            HStack {
                                Image(systemName: "folder.badge.plus")
                                Text(selectedFolderURL?.lastPathComponent ?? String(localized: "Select External Empty Folder (iCloud / Local)"))
                                    .foregroundStyle(selectedFolderURL == nil ? .secondary : .primary)
                                Spacer()
                                Image(systemName: "chevron.right")
                                    .font(.footnote)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    } else {
                        Text("An isolated encrypted vault will be created in this app's local sandbox.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                
                Section {
                    HStack {
                        if isShowingPassword {
                            TextField("Master Password", text: $password)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                        } else {
                            SecureField("Master Password", text: $password)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                        }
                        
                        Button {
                            isShowingPassword.toggle()
                        } label: {
                            Image(systemName: isShowingPassword ? "eye.slash" : "eye")
                                .foregroundStyle(.secondary)
                        }
                    }
                    
                    SecureField("Confirm Master Password", text: $confirmPassword)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    
                    if !password.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text("Password Strength: \(Text(passwordStrength.localizedLabel))")
                                    .font(.caption)
                                    .foregroundStyle(strengthColor)
                                Spacer()
                            }
                            GeometryReader { geo in
                                ZStack(alignment: .leading) {
                                    Capsule()
                                        .fill(Color(.systemGray5))
                                    Capsule()
                                        .fill(strengthColor)
                                        .frame(width: geo.size.width * strengthPercent)
                                }
                            }
                            .frame(height: 4)
                        }
                    }
                    
                    if !confirmPassword.isEmpty && password != confirmPassword {
                        Text("Passwords do not match")
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                } header: {
                    Text("Set Master Password")
                } footer: {
                    if let errorMessage {
                        Text(errorMessage)
                            .foregroundStyle(.red)
                    } else {
                        Text("gocryptfs uses strong AES-GCM-256 encryption. Please keep your password safe; forgotten passwords cannot be recovered.")
                    }
                }
                
                Section {
                    Button {
                        performCreation()
                    } label: {
                        HStack {
                            Spacer()
                            if isCreating {
                                ProgressView()
                                    .padding(.trailing, 4)
                            }
                            Text(isCreating ? "Initializing vault..." : "Create and Initialize")
                                .fontWeight(.semibold)
                            Spacer()
                        }
                    }
                    .disabled(!canCreate)
                }
            }
            .navigationTitle("New Vault")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
            .sheet(isPresented: $isSelectingFolder) {
                FolderPicker { url in
                    selectedFolderURL = url
                    if vaultName.isEmpty {
                        vaultName = url.lastPathComponent
                    }
                }
            }
        }
    }
    
    private var strengthColor: Color {
        switch passwordStrength {
        case .tooShort, .weak: return .red
        case .fair: return .orange
        case .strong: return .green
        @unknown default: return .gray
        }
    }
    
    private var strengthPercent: CGFloat {
        switch passwordStrength {
        case .tooShort: return 0.25
        case .weak: return 0.5
        case .fair: return 0.75
        case .strong: return 1.0
        @unknown default: return 0.0
        }
    }
    
    private func performCreation() {
        guard canCreate else { return }
        isCreating = true
        errorMessage = nil
        
        Task {
            do {
                let targetURL: URL
                if useLocalSandbox {
                    let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
                    targetURL = docs.appendingPathComponent("vault_\(UUID().uuidString)", isDirectory: true)
                    try FileManager.default.createDirectory(at: targetURL, withIntermediateDirectories: true)
                } else {
                    guard let sel = selectedFolderURL else { return }
                    targetURL = sel
                }
                
                let isAccessing = targetURL.startAccessingSecurityScopedResource()
                defer {
                    if isAccessing { targetURL.stopAccessingSecurityScopedResource() }
                }
                
                // Create gocryptfs vault
                try GocryptfsEngine.createVault(at: targetURL, password: password)
                
                let bookmark = try targetURL.bookmarkData(
                    options: .minimalBookmark,
                    includingResourceValuesForKeys: nil,
                    relativeTo: nil
                )
                
                let vault = store.addCreatedVault(
                    url: targetURL,
                    name: vaultName.trimmingCharacters(in: .whitespacesAndNewlines),
                    bookmark: bookmark
                )
                
                isCreating = false
                dismiss()
                onCreated(vault)
            } catch VaultError.directoryNotEmpty {
                isCreating = false
                errorMessage = String(localized: "The selected folder is not empty. gocryptfs vault creation requires an empty directory.")
            } catch VaultError.vaultAlreadyExists {
                isCreating = false
                errorMessage = String(localized: "A gocryptfs vault already exists in this directory.")
            } catch {
                isCreating = false
                errorMessage = String(localized: "Failed to create vault: \(error.localizedDescription)")
            }
        }
    }
}

private extension PasswordStrength {
    var localizedLabel: LocalizedStringKey {
        switch self {
        case .tooShort: return "Too Short"
        case .weak: return "Weak"
        case .fair: return "Fair"
        case .strong: return "Strong"
        @unknown default: return ""
        }
    }
}
