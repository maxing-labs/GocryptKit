import SwiftUI
import VaultCore

/// "Create New Vault" modal sheet.
///
/// Responsible solely for gathering parameters and returning creation results; does not perform mounting.
/// Once created, the main window populates the ciphertext directory, leaving mount timing to the user.
struct CreateVaultView: View {
    /// Callback returning the ciphertext directory URL upon successful creation.
    let onCreated: (URL) -> Void
    let onCancel: () -> Void

    @State private var cipherPath: String = ""
    @State private var password: String = ""
    @State private var confirmation: String = ""
    @State private var isShowingPassword = false
    @State private var acknowledgedNoRecovery = false
    @State private var isBusy = false
    @State private var errorMessage: String? = nil

    private var strength: PasswordStrength { PasswordStrength.evaluate(password) }

    private var passwordsMatch: Bool {
        !confirmation.isEmpty && password == confirmation
    }

    private var canCreate: Bool {
        !isBusy
            && !cipherPath.isEmpty
            && strength > .tooShort
            && passwordsMatch
            && acknowledgedNoRecovery
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(loc("Create New Vault"))
                .font(.title3)
                .fontWeight(.bold)

            VStack(alignment: .leading, spacing: 4) {
                Text(loc("Location for new vault (must be an empty directory):"))
                    .font(.subheadline)
                    .fontWeight(.medium)
                HStack {
                    TextField(loc("Choose an empty directory"), text: $cipherPath)
                        .textFieldStyle(.roundedBorder)
                    Button(loc("Choose…")) { selectDirectory() }
                }
                if let hint = directoryHint {
                    Text(hint.text)
                        .font(.caption)
                        .foregroundColor(hint.isProblem ? .red : .secondary)
                }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(loc("Password:"))
                    .font(.subheadline)
                    .fontWeight(.medium)
                HStack(spacing: 4) {
                    if isShowingPassword {
                        TextField(loc("Set vault password (never stored anywhere)"), text: $password)
                    } else {
                        SecureField(loc("Set vault password (never stored anywhere)"), text: $password)
                    }

                    Button {
                        isShowingPassword.toggle()
                    } label: {
                        Image(systemName: isShowingPassword ? "eye" : "eye.slash")
                            .foregroundStyle(isShowingPassword ? Color.accentColor : Color.secondary)
                    }
                    .buttonStyle(.plain)
                    .help(isShowingPassword ? loc("Hide password") : loc("Show password"))
                }
                .textFieldStyle(.roundedBorder)
                strengthMeter
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(loc("Confirm password:"))
                    .font(.subheadline)
                    .fontWeight(.medium)
                HStack(spacing: 4) {
                    if isShowingPassword {
                        TextField(loc("Enter the same password again"), text: $confirmation)
                    } else {
                        SecureField(loc("Enter the same password again"), text: $confirmation)
                    }
                }
                .textFieldStyle(.roundedBorder)
                if !confirmation.isEmpty && !passwordsMatch {
                    Text(loc("Passwords do not match"))
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }

            // This is not a legal disclaimer, but technical reality: the master key is wrapped
            // solely by the password in gocryptfs.conf, without backdoors, recovery keys, or support overrides.
            VStack(alignment: .leading, spacing: 6) {
                Text(loc("Lost password = permanent data loss"))
                    .font(.subheadline)
                    .fontWeight(.semibold)
                Text(loc("The vault's master key is only wrapped by this password and stored in gocryptfs.conf. There is no recovery code, no backdoor, and no one can recover it for you. Please save it in a password manager first."))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Toggle(loc("I have saved the password safely and understand it cannot be recovered if lost"), isOn: $acknowledgedNoRecovery)
                    .font(.caption)
            }
            .padding(10)
            .background(Color.orange.opacity(0.1))
            .cornerRadius(8)

            if let err = errorMessage {
                Text(err)
                    .font(.caption)
                    .foregroundColor(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Spacer()
                Button(loc("Cancel")) { onCancel() }
                    .keyboardShortcut(.cancelAction)
                Button(action: performCreate) {
                    if isBusy {
                        ProgressView().controlSize(.small)
                    } else {
                        Text(loc("Create"))
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canCreate)
            }
        }
        .padding(20)
        .frame(width: 480)
    }

    private var strengthMeter: some View {
        HStack(spacing: 8) {
            ForEach(PasswordStrength.allCases.dropFirst(), id: \.rawValue) { level in
                RoundedRectangle(cornerRadius: 2)
                    .fill(strength >= level && !password.isEmpty ? strengthColor : Color.secondary.opacity(0.2))
                    .frame(height: 4)
            }
            Text(password.isEmpty ? "" : "\(strength.localizedLabel) · \(strength.localizedAdvice)")
                .font(.caption)
                .foregroundColor(.secondary)
                .frame(width: 260, alignment: .leading)
        }
    }

    private var strengthColor: Color {
        switch strength {
        case .tooShort, .weak: return .red
        case .fair: return .orange
        case .strong: return .green
        }
    }

    /// Surfaces validation issues before the user clicks "Create", saving a slow scrypt derivation
    /// only to fail with "directory not empty". The engine independently re-validates.
    private var directoryHint: (text: String, isProblem: Bool)? {
        guard !cipherPath.isEmpty else { return nil }
        let path = (cipherPath as NSString).expandingTildeInPath
        let fm = FileManager.default

        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDir) else {
            return (loc("Directory does not exist"), true)
        }
        guard isDir.boolValue else {
            return (loc("This is a file, not a directory"), true)
        }
        if fm.fileExists(atPath: (path as NSString).appendingPathComponent("gocryptfs.conf")) {
            return (loc("A vault already exists here; please mount it directly"), true)
        }
        let contents = (try? fm.contentsOfDirectory(atPath: path))?.filter { $0 != ".DS_Store" } ?? []
        if !contents.isEmpty {
            return (loc("Directory is not empty (\(contents.count) items). Existing files will not be encrypted; please choose an empty directory"), true)
        }
        return (loc("Empty directory, ready to create"), false)
    }

    private func selectDirectory() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = loc("Choose")
        panel.message = loc("Choose an empty directory to store encrypted data")
        if panel.runModal() == .OK, let url = panel.url {
            cipherPath = url.path
        }
    }

    private func performCreate() {
        errorMessage = nil
        isBusy = true
        let dir = URL(fileURLWithPath: (cipherPath as NSString).expandingTildeInPath)
        let pwd = password

        // Default scrypt logN=16 takes 1-2 seconds; must not block the main thread.
        Task.detached(priority: .userInitiated) {
            do {
                _ = try GocryptfsEngine.createVault(at: dir, password: pwd)
                await MainActor.run {
                    isBusy = false
                    password = ""
                    confirmation = ""
                    onCreated(dir)
                }
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    isBusy = false
                }
            }
        }
    }
}

private extension PasswordStrength {
    var localizedLabel: String {
        switch self {
        case .tooShort: return loc("Too short")
        case .weak:     return loc("Weak")
        case .fair:     return loc("Fair")
        case .strong:   return loc("Strong")
        @unknown default: return ""
        }
    }

    var localizedAdvice: String {
        switch self {
        case .tooShort: return loc("At least \(Self.minimumLength) characters required")
        case .weak:     return loc("Make it longer; mix uppercase, lowercase, numbers, and symbols")
        case .fair:     return loc("A bit longer would be safer")
        case .strong:   return loc("Sufficient strength")
        @unknown default: return ""
        }
    }
}
