import SwiftUI
import VaultCore

struct UnlockVaultSheet: View {
    let vault: iOSVault
    let onUnlocked: () -> Void
    
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var isShowingPassword = false
    @State private var isUnlocking = false
    @State private var errorMessage: String?
    
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack {
                        Image(systemName: "lock.shield.fill")
                            .font(.system(size: 36))
                            .foregroundStyle(.blue)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(vault.name)
                                .font(.headline)
                            Text("gocryptfs Vault")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 8)
                }
                
                Section {
                    HStack {
                        if isShowingPassword {
                            TextField("Enter unlock password", text: $password)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                        } else {
                            SecureField("Enter unlock password", text: $password)
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
                } header: {
                    Text("Password Credential")
                } footer: {
                    if let errorMessage {
                        Text(errorMessage)
                            .foregroundStyle(.red)
                    }
                }
                
                Section {
                    Button {
                        performUnlock()
                    } label: {
                        HStack {
                            Spacer()
                            if isUnlocking {
                                ProgressView()
                                    .padding(.trailing, 4)
                            }
                            Text(isUnlocking ? "Unlocking..." : "Unlock and Open")
                                .fontWeight(.semibold)
                            Spacer()
                        }
                    }
                    .disabled(password.isEmpty || isUnlocking)
                }
            }
            .navigationTitle("Unlock Vault")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
        }
    }
    
    private func performUnlock() {
        guard !password.isEmpty else { return }
        isUnlocking = true
        errorMessage = nil
        
        Task {
            do {
                try VaultSession.shared.unlock(vault: vault, password: password)
                isUnlocking = false
                dismiss()
                onUnlocked()
            } catch VaultError.authFailed {
                isUnlocking = false
                errorMessage = String(localized: "Incorrect password. Please try again.")
            } catch VaultError.configNotFound {
                isUnlocking = false
                errorMessage = String(localized: "gocryptfs.conf not found. This directory may not be a valid gocryptfs vault.")
            } catch {
                isUnlocking = false
                errorMessage = String(localized: "Failed to unlock: \(error.localizedDescription)")
            }
        }
    }
}
