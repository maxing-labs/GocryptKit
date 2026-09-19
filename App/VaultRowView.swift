import SwiftUI
import VaultCore

/// A single vault row in the list. Displays name and status when collapsed; expands to show full details and actions.
///
/// Passwords exist solely in this view's `@State` and are immediately zeroed out upon mount success or failure,
/// never written back to `Vault` (which persists to disk).
struct VaultRowView: View {
    let vault: Vault
    let store: VaultStore
    @Binding var isExpanded: Bool

    @Environment(\.locale) private var locale

    @State private var password = ""
    @State private var isShowingPassword = false
    @State private var viewModel = VaultRowViewModel()
    @State private var editedName = ""
    @State private var isConfirmingRemoval = false
    @State private var isConfirmingForceUnmount = false
    @FocusState private var passwordFocused: Bool

    private var isMounted: Bool { store.isMounted(vault) }
    private var actualMountPoint: String? { store.actualMountPoint(vault) }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            if isExpanded {
                Divider().padding(.vertical, 10)
                details
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .strokeBorder(Color(nsColor: .separatorColor), lineWidth: 1)
        )
        // Must populate on onAppear as well. Adding an existing vault creates the row already expanded,
        // so onChange will not fire, leaving the name text field blank on first display.
        .onAppear {
            editedName = vault.name
            if store.requestedFocusVaultID == vault.id {
                focusPasswordField()
                store.clearFocus()
            }
        }
        .onChange(of: store.requestedFocusVaultID) { _, newID in
            if newID == vault.id {
                focusPasswordField()
                store.clearFocus()
            }
        }
        .onChange(of: isExpanded) { _, expanded in
            if expanded {
                editedName = vault.name
            } else {
                // Commits renaming on collapse. Relying solely on onSubmit loses changes if user modifies
                // name and collapses without pressing Return. `rename` internally filters empty/identical strings.
                store.rename(vault, to: editedName)
                password = ""
                isShowingPassword = false
                viewModel.errorMessage = nil
                viewModel.canForceUnmount = false
            }
        }
        .confirmationDialog(String(localized: "Remove \"\(vault.name)\" from list?"),
                            isPresented: $isConfirmingRemoval,
                            titleVisibility: .visible) {
            Button("Remove", role: .destructive) { store.remove(vault) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This only removes it from this list. Encrypted directory and data will not be modified, and can be added back later.")
        }
        .confirmationDialog(String(localized: "Force unmount \"\(vault.name)\"?"),
                            isPresented: $isConfirmingForceUnmount,
                            titleVisibility: .visible) {
            Button("Force Unmount", role: .destructive) {
                viewModel.performForceUnmount(vault: vault, actualMountPoint: actualMountPoint, store: store)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Force unmounting immediately detaches the volume. Any unsaved changes in files currently open in other applications may be lost.")
        }
    }

    // MARK: - Header (Always Visible)

    private var header: some View {
        HStack(spacing: 10) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { isExpanded.toggle() }
            } label: {
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .rotationEffect(.degrees(isExpanded ? 90 : 0))
                    .frame(width: 12)
            }
            .buttonStyle(.plain)
            .accessibilityLabel(isExpanded ? String(localized: "Collapse") : String(localized: "Expand"))

            Image(systemName: isMounted ? "lock.open.fill" : "lock.fill")
                .font(.system(size: 15))
                .foregroundStyle(isMounted ? Color.accentColor : Color.secondary)
                .frame(width: 18)

            VStack(alignment: .leading, spacing: 1) {
                Text(vault.name)
                    .font(.body.weight(.medium))
                    .lineLimit(1)
                Text(abbreviate(vault.cipherDirPath))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer(minLength: 8)

            if viewModel.isBusy {
                ProgressView().controlSize(.small)
            } else {
                Text(isMounted ? String(localized: "Mounted") : String(localized: "Unmounted"))
                    .font(.caption)
                    .foregroundStyle(isMounted ? Color.green : Color.secondary)
            }

            Button(String(localized: "Remove from List…")) { isConfirmingRemoval = true }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(isMounted || viewModel.isBusy)
                .help(isMounted ? String(localized: "Unmount before removing from the list.") : String(localized: "Only removes list entry; data on disk is untouched."))

            primaryButton
        }
        .contentShape(Rectangle())
        .onTapGesture {
            withAnimation(.easeInOut(duration: 0.15)) { isExpanded.toggle() }
        }
    }

    /// Directly provides "Unmount" when mounted; when unmounted, clicking "Mount" expands to accept password.
    @ViewBuilder
    private var primaryButton: some View {
        if isMounted {
            Button(String(localized: "Unmount")) { performUnmount() }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(viewModel.isBusy)
        } else {
            Button(String(localized: "Mount")) {
                if isExpanded && !password.isEmpty {
                    performMount()
                } else {
                    withAnimation(.easeInOut(duration: 0.15)) { isExpanded = true }
                    if password.isEmpty {
                        focusPasswordField()
                    }
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
            .disabled(viewModel.isBusy)
        }
    }

    // MARK: - Expanded Details

    private var details: some View {
        VStack(alignment: .leading, spacing: 12) {
            field(String(localized: "Name")) {
                TextField("Vault display name", text: $editedName)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { store.rename(vault, to: editedName) }
            }

            field(String(localized: "Encrypted Directory")) {
                HStack(spacing: 6) {
                    Text(vault.cipherDirPath)
                        .font(.callout)
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button("Reveal in Finder") { revealInFinder(vault.cipherDirPath) }
                        .controlSize(.small)
                }
            }

            field(String(localized: "Mount Point")) {
                HStack(spacing: 6) {
                    Text(abbreviate(actualMountPoint ?? vault.mountPointPath))
                        .font(.callout)
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    if isMounted {
                        Button("Open") { revealInFinder(actualMountPoint ?? vault.mountPointPath) }
                            .controlSize(.small)
                    } else {
                        Button("Change…") { chooseMountPoint() }
                            .controlSize(.small)
                    }
                }
            }

            if isMounted {
                // Mount point differs from registered path, most likely mounted elsewhere via CLI.
                // Explicit warning is preferable to silently displaying mismatched paths. Comparisons must use
                // canonicalKey: the kernel reports resolved symlink paths, and raw string equality falsely flags
                // /tmp vs /private/tmp differences.
                if let actual = actualMountPoint,
                   Vault.canonicalKey(path: actual) != Vault.canonicalKey(path: vault.mountPointPath) {
                    Label("This volume is currently mounted elsewhere, not at the registered location.",
                          systemImage: "info.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                field(String(localized: "Password")) {
                    HStack(spacing: 6) {
                        HStack(spacing: 4) {
                            if isShowingPassword {
                                TextField("Enter password (never stored anywhere)", text: $password)
                                    .focused($passwordFocused)
                            } else {
                                SecureField("Enter password (never stored anywhere)", text: $password)
                                    .focused($passwordFocused)
                            }

                            Button {
                                isShowingPassword.toggle()
                                focusPasswordField()
                            } label: {
                                Image(systemName: isShowingPassword ? "eye" : "eye.slash")
                                    .foregroundStyle(isShowingPassword ? Color.accentColor : Color.secondary)
                            }
                            .buttonStyle(.plain)
                            .help(isShowingPassword ? String(localized: "Hide password", locale: locale) : String(localized: "Show password", locale: locale))
                        }
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { if !password.isEmpty { performMount() } }

                        Button(String(localized: "Mount")) { performMount() }
                            .buttonStyle(.borderedProminent)
                            .disabled(viewModel.isBusy || password.isEmpty)
                    }
                }
            }

            if let errorMessage = viewModel.errorMessage {
                VStack(alignment: .leading, spacing: 6) {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)

                    if viewModel.canForceUnmount {
                        HStack {
                            Button(String(localized: "Force Unmount…")) {
                                isConfirmingForceUnmount = true
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            .tint(.red)
                            .disabled(viewModel.isBusy)

                            Text(String(localized: "Closes active sessions immediately"))
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    private func focusPasswordField() {
        DispatchQueue.main.async {
            passwordFocused = true
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            passwordFocused = true
        }
    }

    private func field<Content: View>(_ label: String,
                                      @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            content()
        }
    }

    // MARK: - Actions

    private func performMount() {
        guard !password.isEmpty else { return }
        let pwd = password
        password = ""
        isShowingPassword = false
        viewModel.performMount(vault: vault, password: pwd, store: store)
    }

    private func performUnmount() {
        viewModel.performUnmount(vault: vault, actualMountPoint: actualMountPoint, store: store)
    }

    private func chooseMountPoint() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.message = String(localized: "Choose mount point for \"\(vault.name)\"")
        panel.directoryURL = vault.mountPointURL.deletingLastPathComponent()
        if panel.runModal() == .OK, let url = panel.url {
            store.setMountPoint(vault, to: url.path)
        }
    }

    private func revealInFinder(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    /// Formats paths under home directory with ~/... to avoid truncating meaningful path suffixes.
    private func abbreviate(_ path: String) -> String {
        (path as NSString).abbreviatingWithTildeInPath
    }
}
