import SwiftUI
import VaultCore

struct ContentView: View {
    @State private var mountManager = MountManager.shared
    var store: VaultStore
    @State private var expandedVaultIDs: Set<UUID> = []
    @State private var isCreatingVault = false
    @State private var addError: String?
    @State private var isCheckingExtension = false

    init(store: VaultStore = VaultStore()) {
        self.store = store
    }

    /// The mount table may be modified outside the app (CLI, Finder eject, other terminal sessions).
    /// `getfsstat` is inexpensive; polling periodically is more reliable than guessing which events to observe.
    private let mountPoll = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    @ObservedObject private var langManager = LanguageManager.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            if let warning = extensionWarning { warning }
            vaultList
            footer
        }
        .padding(16)
        .frame(minWidth: 560, minHeight: 420)
        .environment(\.locale, langManager.currentLocale)
        .id(langManager.currentLanguage)
        .onReceive(mountPoll) { _ in store.refreshMountState() }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didMountNotification)) { _ in
            store.refreshMountState()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didUnmountNotification)) { _ in
            store.refreshMountState()
        }
        .onAppear {
            store.refreshMountState()
            refreshExtensionStatus()
            if let focusID = store.requestedFocusVaultID {
                expandedVaultIDs.insert(focusID)
            }
        }
        .onChange(of: store.requestedFocusVaultID) { _, newID in
            if let newID {
                withAnimation(.easeInOut(duration: 0.15)) {
                    expandedVaultIDs.insert(newID)
                }
            }
        }
        .sheet(isPresented: $isCreatingVault) {
            CreateVaultView(
                onCreated: { url in
                    isCreatingVault = false
                    let vault = store.addCreated(cipherDir: url)
                    expandedVaultIDs = [vault.id]
                },
                onCancel: { isCreatingVault = false }
            )
            .environment(\.locale, langManager.currentLocale)
        }
    }

    // MARK: - Header

    private var appVersionString: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.3.0"
        return "v\(version)"
    }

    private var header: some View {
        HStack {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text("GocryptKit")
                    .font(.title2)
                    .fontWeight(.bold)

                Button {
                    openAbout()
                } label: {
                    Text(appVersionString)
                        .font(.caption2)
                        .fontWeight(.semibold)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.12))
                        .cornerRadius(4)
                }
                .buttonStyle(.plain)
                .help(loc("View About GocryptKit"))
            }
            Spacer()
            HStack(spacing: 6) {
                if isCheckingExtension {
                    ProgressView().controlSize(.small).scaleEffect(0.6).frame(width: 8, height: 8)
                } else {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 8, height: 8)
                }
                Text(statusLabel)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var statusColor: Color {
        switch mountManager.extensionStatus {
        case .enabled: return .green
        case .disabled, .notRegistered: return .orange
        case .unknown: return .gray
        }
    }

    private var statusLabel: String {
        if isCheckingExtension { return loc("Checking extension…") }
        switch mountManager.extensionStatus {
        case .enabled: return loc("FSKit extension is enabled")
        case .disabled: return loc("Extension is disabled")
        case .notRegistered: return loc("Extension not registered")
        case .unknown: return loc("Extension status unknown")
        }
    }

    /// Diagnostic advisory displayed when the extension is unavailable. Solutions differ per cause,
    /// so we avoid collapsing them into a generic "Please enable extension" message.
    @ViewBuilder
    private var extensionWarning: (some View)? {
        switch mountManager.extensionStatus {
        case .enabled:
            EmptyView().hidden().frame(height: 0)
        case .disabled:
            warningBox(
                title: loc("FSKit extension is disabled by system; cannot mount volumes"),
                detail: loc("System Settings → General → Login Items & Extensions → scroll to bottom and click 'File System Extensions' → enable GocryptKit.\nThis is a macOS security confirmation for third-party file systems; the app cannot enable it automatically."),
                showsSettingsButton: true
            )
        case .notRegistered:
            warningBox(
                title: loc("System has not registered this extension yet"),
                detail: loc("If the app was just installed or updated, quit and reopen it to register the extension. Then go to System Settings → General → Login Items & Extensions → File System Extensions and enable GocryptKit."),
                showsSettingsButton: true
            )
        case .unknown:
            warningBox(
                title: loc("Unable to confirm extension status"),
                detail: loc("Probe could not be completed. You can click 'Recheck' to try again; if mounting works normally, you can safely ignore this."),
                showsSettingsButton: false
            )
        }
    }

    private func warningBox(title: String, detail: String, showsSettingsButton: Bool) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.subheadline)
                .fontWeight(.medium)
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                if showsSettingsButton {
                    Button(loc("Open System Settings")) { openExtensionSettings() }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                }
                Button(loc("Recheck")) { refreshExtensionStatus() }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .disabled(isCheckingExtension)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.1))
        .cornerRadius(8)
    }

    /// Directly opens the "Login Items & Extensions" settings pane to spare users from manual navigation.
    private func openExtensionSettings() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.ExtensionsPreferences") else { return }
        NSWorkspace.shared.open(url)
    }

    private func openAbout() {
        if let appDelegate = NSApp.delegate as? AppDelegate {
            appDelegate.openAboutPanel(nil)
        } else {
            NSApp.activate(ignoringOtherApps: true)
            NSApp.orderFrontStandardAboutPanel(nil)
        }
    }

    /// Probing spawns an extension process and takes 1-2 seconds, so perform it asynchronously off the main thread.
    private func refreshExtensionStatus() {
        guard !isCheckingExtension else { return }
        isCheckingExtension = true
        // Access singleton directly rather than capturing mountManager (MainActor-isolated property unsafe in detached tasks).
        Task.detached(priority: .userInitiated) {
            MountManager.shared.checkExtensionStatus()
            await MainActor.run { isCheckingExtension = false }
        }
    }

    // MARK: - Vault List

    @ViewBuilder
    private var vaultList: some View {
        if store.vaults.isEmpty {
            emptyState
        } else {
            ScrollView {
                LazyVStack(spacing: 8) {
                    ForEach(store.vaults) { vault in
                        VaultRowView(
                            vault: vault,
                            store: store,
                            isExpanded: Binding(
                                get: { expandedVaultIDs.contains(vault.id) },
                                set: { expanded in
                                    if expanded {
                                        expandedVaultIDs.insert(vault.id)
                                    } else {
                                        expandedVaultIDs.remove(vault.id)
                                    }
                                }
                            )
                        )
                        .id(vault.id)
                    }
                }
                .padding(.vertical, 2)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "folder.badge.questionmark")
                .font(.system(size: 34))
                .foregroundStyle(.tertiary)
            Text(loc("No Vaults Added Yet"))
                .font(.headline)
            Text(loc("Add an existing gocryptfs directory, or create a new one."))
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack(spacing: 12) {
                Button(loc("Add Existing Vault…")) { addExistingVault() }
                    .buttonStyle(.borderedProminent)
                Button(loc("Create New Vault…")) { isCreatingVault = true }
                    .buttonStyle(.bordered)
            }
            .padding(.top, 4)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Footer

    private var footer: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let addError {
                Label(addError, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 8) {
                Button(loc("Add Existing Vault…")) { addExistingVault() }
                    .buttonStyle(.bordered)
                    .keyboardShortcut("o", modifiers: .command)
                Button(loc("Create New Vault…")) { isCreatingVault = true }
                    .buttonStyle(.bordered)
                    .keyboardShortcut("n", modifiers: .command)
                Spacer()
                if !store.vaults.isEmpty {
                    Text(loc("\(store.vaults.count) vaults, \(store.mountedCount) mounted"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func addExistingVault() {
        addError = nil
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.message = loc("Choose an existing gocryptfs encrypted directory")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let vault = try store.addExisting(cipherDir: url)
            expandedVaultIDs = [vault.id]
        } catch let err as VaultRegistryError {
            addError = err.userFacingMessage()
        } catch {
            addError = error.localizedDescription
        }
    }
}

extension VaultRegistryError {
    func userFacingMessage() -> String {
        switch self {
        case .notAVault(let path):
            return loc("No gocryptfs.conf found in \(path); not a valid gocryptfs vault.")
        case .duplicate(let name):
            return loc("This directory is already in the list (\(name)).")
        }
    }
}
