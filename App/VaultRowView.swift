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

    @State private var password = ""
    @State private var isShowingPassword = false
    @State private var isMountReadOnly = false
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
            isMountReadOnly = vault.isReadOnlyDefault
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
                isMountReadOnly = vault.isReadOnlyDefault
            }
        }
        .onChange(of: vault.isReadOnlyDefault) { _, newDefault in
            if !isMounted {
                isMountReadOnly = newDefault
            }
        }
        .onChange(of: password) { _, _ in
            if viewModel.errorMessage != nil {
                viewModel.errorMessage = nil
            }
        }
        .confirmationDialog(loc("Remove \"\(vault.name)\" from list?"),
                            isPresented: $isConfirmingRemoval,
                            titleVisibility: .visible) {
            Button(loc("Remove"), role: .destructive) { store.remove(vault) }
            Button(loc("Cancel"), role: .cancel) {}
        } message: {
            Text(loc("This only removes it from this list. Encrypted directory and data will not be modified, and can be added back later."))
        }
        .confirmationDialog(loc("Force unmount \"\(vault.name)\"?"),
                            isPresented: $isConfirmingForceUnmount,
                            titleVisibility: .visible) {
            Button(loc("Force Unmount"), role: .destructive) {
                viewModel.performForceUnmount(vault: vault, actualMountPoint: actualMountPoint, store: store)
            }
            Button(loc("Cancel"), role: .cancel) {}
        } message: {
            Text(loc("Force unmounting immediately detaches the volume. Any unsaved changes in files currently open in other applications may be lost."))
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
            .accessibilityLabel(isExpanded ? loc("Collapse") : loc("Expand"))

            let isReadOnlyMounted = isMounted && store.isReadOnly(vault)

            Image(systemName: isMounted ? "lock.open.fill" : "lock.fill")
                .font(.system(size: 15))
                .foregroundStyle(isMounted ? (isReadOnlyMounted ? Color.orange : Color.accentColor) : Color.secondary)
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
                if isMounted {
                    if isReadOnlyMounted {
                        HStack(spacing: 4) {
                            Circle()
                                .fill(Color.orange)
                                .frame(width: 6, height: 6)
                            Text(loc("Mounted (Read-Only)"))
                                .font(.caption.weight(.medium))
                                .foregroundStyle(Color.orange)
                        }
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.orange.opacity(0.12))
                        .clipShape(Capsule())
                    } else {
                        HStack(spacing: 4) {
                            Circle()
                                .fill(Color.green)
                                .frame(width: 6, height: 6)
                            Text(loc("Mounted"))
                                .font(.caption)
                                .foregroundStyle(Color.green)
                        }
                    }
                } else {
                    Text(loc("Unmounted"))
                        .font(.caption)
                        .foregroundStyle(Color.secondary)
                }
            }

            Button(loc("Remove from List…")) { isConfirmingRemoval = true }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(isMounted || viewModel.isBusy)
                .help(isMounted ? loc("Unmount before removing from the list.") : loc("Only removes list entry; data on disk is untouched."))

            primaryButton
        }
        .contentShape(Rectangle())
        .onTapGesture {
            withAnimation(.easeInOut(duration: 0.15)) { isExpanded.toggle() }
        }
    }

    /// Directly provides "Unmount" when mounted; when unmounted, provides primary action and pull-down menu for read-only.
    @ViewBuilder
    private var primaryButton: some View {
        if isMounted {
            Button(loc("Unmount")) { performUnmount() }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(viewModel.isBusy)
        } else {
            Menu {
                Button(loc("Mount (Read-Write)")) {
                    triggerMountAction(readOnly: false)
                }
                Button(loc("Mount as Read-Only")) {
                    triggerMountAction(readOnly: true)
                }
            } label: {
                Text(loc("Mount"))
            } primaryAction: {
                triggerMountAction()
            }
            .menuStyle(.borderedButton)
            .controlSize(.small)
            .disabled(viewModel.isBusy)
        }
    }

    // MARK: - Expanded Details

    private var details: some View {
        VStack(alignment: .leading, spacing: 12) {
            let isReadOnlyMounted = isMounted && store.isReadOnly(vault)
            if isMounted {
                HStack(spacing: 10) {
                    Image(systemName: isReadOnlyMounted ? "lock.slash.fill" : "lock.open.fill")
                        .font(.title3)
                        .foregroundStyle(isReadOnlyMounted ? Color.orange : Color.green)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(isReadOnlyMounted ? loc("Currently mounted in read-only mode") : loc("Currently mounted in read-write mode"))
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(isReadOnlyMounted ? Color.orange : Color.primary)
                        Text(isReadOnlyMounted ? loc("Files are protected against modification, creation, and deletion.") : loc("Full read and write permissions are enabled."))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                .padding(10)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(isReadOnlyMounted ? Color.orange.opacity(0.08) : Color.green.opacity(0.08))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .strokeBorder(isReadOnlyMounted ? Color.orange.opacity(0.3) : Color.green.opacity(0.2), lineWidth: 1)
                )
            } else {
                field(loc("Password")) {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 6) {
                            HStack(spacing: 4) {
                                if isShowingPassword {
                                    TextField(loc("Enter password (never stored anywhere)"), text: $password)
                                        .focused($passwordFocused)
                                } else {
                                    SecureField(loc("Enter password (never stored anywhere)"), text: $password)
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
                                .help(isShowingPassword ? loc("Hide password") : loc("Show password"))
                            }
                            .textFieldStyle(.roundedBorder)
                            .onSubmit { if !password.isEmpty { performMount() } }

                            Button(isMountReadOnly ? loc("Mount Read-Only") : loc("Mount")) {
                                performMount()
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(viewModel.isBusy || password.isEmpty)
                        }

                        HStack(spacing: 8) {
                            Toggle(isOn: Binding(
                                get: { !isMountReadOnly },
                                set: { isMountReadOnly = !$0 }
                            )) {
                                EmptyView()
                            }
                            .toggleStyle(.switch)
                            .controlSize(.small)
                            .labelsHidden()

                            HStack(spacing: 4) {
                                Image(systemName: !isMountReadOnly ? "pencil" : "lock.slash.fill")
                                    .foregroundStyle(!isMountReadOnly ? Color.secondary : Color.orange)
                                Text(!isMountReadOnly ? loc("Mount in read-write mode") : loc("Mount in read-only mode"))
                                    .font(.caption)
                                    .foregroundStyle(!isMountReadOnly ? Color.secondary : Color.orange)
                            }
                            .onTapGesture {
                                isMountReadOnly.toggle()
                            }
                        }

                        if let errorMessage = viewModel.errorMessage, !isMounted {
                            Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                                .font(.caption)
                                .foregroundStyle(.red)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
            }

            field(loc("Encrypted Directory")) {
                HStack(spacing: 6) {
                    Text(vault.cipherDirPath)
                        .font(.callout)
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button(loc("Reveal in Finder")) { revealInFinder(vault.cipherDirPath) }
                        .controlSize(.small)
                }
            }

            let effectivePath = isMounted
                ? (actualMountPoint ?? vault.mountPointPath)
                : (isMountReadOnly ? vault.readOnlyMountPointPath : vault.mountPointPath)

            field(loc("Mount Point")) {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 6) {
                        Text(abbreviate(effectivePath))
                            .font(.callout)
                            .textSelection(.enabled)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if isMounted && store.isReadOnly(vault) {
                            Text(loc("Read-Only"))
                                .font(.caption2.weight(.semibold))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.orange.opacity(0.15))
                                .foregroundStyle(Color.orange)
                                .clipShape(Capsule())
                        } else if !isMounted && isMountReadOnly {
                            Text(loc("Read-Only"))
                                .font(.caption2.weight(.semibold))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.secondary.opacity(0.15))
                                .foregroundStyle(.secondary)
                                .clipShape(Capsule())
                        }
                        Spacer()
                        if isMounted {
                            Button(loc("Open")) { openMountPoint(actualMountPoint ?? vault.mountPointPath) }
                                .controlSize(.small)
                        } else {
                            Button(loc("Change…")) { chooseMountPoint() }
                                .controlSize(.small)
                        }
                    }

                    if let warning = mountPointPreflightWarning(for: effectivePath) {
                        HStack(spacing: 4) {
                            Image(systemName: "exclamationmark.triangle")
                            Text(warning)
                        }
                        .font(.caption)
                        .foregroundStyle(.orange)
                    }
                }
            }

            Toggle(isOn: Binding(
                get: { vault.isReadOnlyDefault },
                set: { store.setDefaultReadOnly(vault, isReadOnly: $0) }
            )) {
                Text(loc("Always mount as read-only by default (saved to preferences)"))
                    .font(.callout)
            }
            .toggleStyle(.checkbox)
            .help(loc("Automatically select read-only mode when mounting this vault."))

            field(loc("Name")) {
                TextField(loc("Vault display name"), text: $editedName)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { store.rename(vault, to: editedName) }
            }

            if isMounted {
                // Mount point differs from registered path, most likely mounted elsewhere via CLI.
                // Explicit warning is preferable to silently displaying mismatched paths. Comparisons must use
                // canonicalKey: the kernel reports resolved symlink paths, and raw string equality falsely flags
                // /tmp vs /private/tmp differences.
                if let actual = actualMountPoint,
                   Vault.canonicalKey(path: actual) != Vault.canonicalKey(path: vault.mountPointPath),
                   Vault.canonicalKey(path: actual) != Vault.canonicalKey(path: vault.readOnlyMountPointPath) {
                    Label(loc("This volume is currently mounted elsewhere, not at the registered location."),
                          systemImage: "info.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            if isMounted, let errorMessage = viewModel.errorMessage {
                VStack(alignment: .leading, spacing: 6) {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)

                    if viewModel.canForceUnmount {
                        HStack {
                            Button(loc("Force Unmount…")) {
                                isConfirmingForceUnmount = true
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            .tint(.red)
                            .disabled(viewModel.isBusy)

                            Text(loc("Closes active sessions immediately"))
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

    private func triggerMountAction(readOnly: Bool? = nil) {
        if let ro = readOnly {
            isMountReadOnly = ro
        } else {
            isMountReadOnly = vault.isReadOnlyDefault
        }
        if isExpanded && !password.isEmpty {
            performMount()
        } else {
            withAnimation(.easeInOut(duration: 0.15)) { isExpanded = true }
            if password.isEmpty {
                focusPasswordField()
            }
        }
    }

    private func performMount() {
        guard !password.isEmpty else { return }
        let pwd = password
        let ro = isMountReadOnly
        password = ""
        isShowingPassword = false
        viewModel.performMount(vault: vault, password: pwd, readOnly: ro, store: store)
    }

    private func performUnmount() {
        viewModel.performUnmount(
            vault: vault,
            actualMountPoint: actualMountPoint,
            store: store,
            onExpand: {
                withAnimation(.easeInOut(duration: 0.15)) {
                    isExpanded = true
                }
            }
        )
    }

    private func chooseMountPoint() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.message = loc("Choose mount point for \"\(vault.name)\"")
        panel.directoryURL = vault.mountPointURL.deletingLastPathComponent()
        if panel.runModal() == .OK, let url = panel.url {
            store.setMountPoint(vault, to: url.path)
        }
    }

    private func openMountPoint(_ path: String) {
        let url = URL(fileURLWithPath: path)
        if !NSWorkspace.shared.open(url) {
            NSWorkspace.shared.activateFileViewerSelecting([url])
        }
    }

    private func revealInFinder(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    /// Formats paths under home directory with ~/... to avoid truncating meaningful path suffixes.
    private func abbreviate(_ path: String) -> String {
        (path as NSString).abbreviatingWithTildeInPath
    }

    private func mountPointPreflightWarning(for path: String) -> String? {
        guard !isMounted else { return nil }
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: path, isDirectory: &isDir) {
            if !isDir.boolValue {
                return loc("Mount point exists as a file, not a directory.")
            }
            if let items = try? FileManager.default.contentsOfDirectory(atPath: path), !items.isEmpty {
                return loc("Target directory exists and is not empty.")
            }
        }
        return nil
    }
}
