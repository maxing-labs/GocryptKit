import AppKit
import VaultCore
import OSLog

private let logger = Logger(subsystem: "com.xwei.GocryptKit", category: "MenuBarManager")

@MainActor
final class MenuBarManager: NSObject, NSMenuDelegate {
    private var statusItem: NSStatusItem?
    private weak var appDelegate: AppDelegate?
    private let store: VaultStore
    private var statusPollTimer: Timer?

    /// Set of vault IDs currently being unmounted (anti-reentry / debouncing)
    private var unmountingVaultIDs: Set<UUID> = []
    /// Flag indicating whether "Unmount All" is currently running
    private var isUnmountingAll: Bool = false

    private var currentLocale: Locale {
        let lang = UserDefaults.standard.string(forKey: "appLanguage") ?? "system"
        switch lang {
        case "zh-Hans": return Locale(identifier: "zh-Hans")
        case "en": return Locale(identifier: "en")
        default: return Locale.autoupdatingCurrent
        }
    }

    init(appDelegate: AppDelegate, store: VaultStore) {
        self.appDelegate = appDelegate
        self.store = store
        super.init()
    }

    func setupStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        self.statusItem = item
        updateStatusIcon()

        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu

        // Periodically synchronizes mount status and dynamically updates the status bar icon
        statusPollTimer?.invalidate()
        statusPollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.periodicRefresh()
            }
        }
    }

    /// Always displays the default branded menu bar icon ("MenuBarIcon"), updating tooltip with mount status.
    func updateStatusIcon() {
        guard let button = statusItem?.button else { return }
        let defaultIcon = NSImage(named: "MenuBarIcon") ?? NSImage(systemSymbolName: "lock.fill", accessibilityDescription: "GocryptKit")
        defaultIcon?.isTemplate = true
        button.image = defaultIcon

        let count = store.mountedCount
        if count > 0 {
            button.toolTip = count == 1
                ? String(localized: "GocryptKit (1 vault mounted)", locale: currentLocale)
                : String(localized: "GocryptKit (\(count) vaults mounted)", locale: currentLocale)
        } else {
            button.toolTip = "GocryptKit"
        }
    }

    private func periodicRefresh() {
        store.refreshMountState()
        updateStatusIcon()
    }

    // MARK: - NSMenuDelegate

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        store.refreshMountState()
        updateStatusIcon()

        let openItem = NSMenuItem(
            title: String(localized: "Open GocryptKit", locale: currentLocale),
            action: #selector(showMainWindow(_:)),
            keyEquivalent: ""
        )
        openItem.target = self
        menu.addItem(openItem)

        menu.addItem(NSMenuItem.separator())

        // MARK: - Dynamic Vault List
        if store.vaults.isEmpty {
            let emptyItem = NSMenuItem(
                title: String(localized: "No Vaults Added", locale: currentLocale),
                action: nil,
                keyEquivalent: ""
            )
            emptyItem.isEnabled = false
            menu.addItem(emptyItem)
        } else {
            let greenConfig = NSImage.SymbolConfiguration(paletteColors: [.systemGreen])
            let orangeConfig = NSImage.SymbolConfiguration(paletteColors: [.systemOrange])
            let grayConfig = NSImage.SymbolConfiguration(paletteColors: [.secondaryLabelColor])

            for vault in store.vaults {
                let isMounted = store.isMounted(vault)
                let isRO = isMounted && store.isReadOnly(vault)
                let item = NSMenuItem()
                item.title = isRO ? "\(vault.name) (\(String(localized: "Read-Only", locale: currentLocale)))" : vault.name

                if isMounted {
                    item.image = NSImage(systemSymbolName: "lock.open.fill", accessibilityDescription: isRO ? "Mounted (Read-Only)" : "Mounted")?
                        .withSymbolConfiguration(isRO ? orangeConfig : greenConfig)

                    let submenu = NSMenu(title: vault.name)

                    let statusHeader = NSMenuItem(
                        title: isRO
                            ? "● \(String(localized: "Mounted (Read-Only)", locale: currentLocale))"
                            : "● \(String(localized: "Mounted (Read-Write)", locale: currentLocale))",
                        action: nil,
                        keyEquivalent: ""
                    )
                    statusHeader.isEnabled = false
                    submenu.addItem(statusHeader)
                    submenu.addItem(NSMenuItem.separator())

                    let actualPath = store.actualMountPoint(vault) ?? vault.mountPointPath
                    let revealItem = NSMenuItem(
                        title: String(localized: "Reveal in Finder", locale: currentLocale),
                        action: #selector(revealVaultInFinder(_:)),
                        keyEquivalent: ""
                    )
                    revealItem.target = self
                    revealItem.image = NSImage(systemSymbolName: "arrow.up.forward.square", accessibilityDescription: nil)
                    revealItem.representedObject = actualPath
                    submenu.addItem(revealItem)

                    let isThisUnmounting = unmountingVaultIDs.contains(vault.id) || isUnmountingAll
                    let unmountTitle = isThisUnmounting
                        ? String(localized: "Unmounting…", locale: currentLocale)
                        : String(localized: "Unmount", locale: currentLocale)

                    let unmountItem = NSMenuItem(
                        title: unmountTitle,
                        action: #selector(unmountVaultAction(_:)),
                        keyEquivalent: ""
                    )
                    unmountItem.target = self
                    unmountItem.image = NSImage(systemSymbolName: "eject", accessibilityDescription: nil)
                    unmountItem.representedObject = vault
                    unmountItem.isEnabled = !isThisUnmounting
                    submenu.addItem(unmountItem)

                    item.submenu = submenu
                } else {
                    item.image = NSImage(systemSymbolName: "lock.fill", accessibilityDescription: "Unmounted")?
                        .withSymbolConfiguration(grayConfig)
                    item.target = self
                    item.action = #selector(focusVaultAction(_:))
                    item.representedObject = vault.id
                }

                menu.addItem(item)
            }

            if store.mountedCount >= 2 {
                menu.addItem(NSMenuItem.separator())
                let isAnyUnmounting = isUnmountingAll || !unmountingVaultIDs.isEmpty
                let unmountAllTitle = isAnyUnmounting
                    ? String(localized: "Unmounting…", locale: currentLocale)
                    : String(localized: "Unmount All", locale: currentLocale)

                let unmountAllItem = NSMenuItem(
                    title: unmountAllTitle,
                    action: #selector(unmountAllAction(_:)),
                    keyEquivalent: ""
                )
                unmountAllItem.target = self
                unmountAllItem.image = NSImage(systemSymbolName: "eject.circle", accessibilityDescription: nil)
                unmountAllItem.isEnabled = !isAnyUnmounting
                menu.addItem(unmountAllItem)
            }
        }

        menu.addItem(NSMenuItem.separator())

        // Language submenu
        let langSubmenu = NSMenu(title: String(localized: "Language", locale: currentLocale))
        let currentLang = UserDefaults.standard.string(forKey: "appLanguage") ?? "system"

        let sysItem = NSMenuItem(
            title: String(localized: "System Language", locale: currentLocale),
            action: #selector(setLanguageSystem(_:)),
            keyEquivalent: ""
        )
        sysItem.target = self
        sysItem.state = (currentLang == "system") ? .on : .off
        langSubmenu.addItem(sysItem)

        let zhItem = NSMenuItem(
            title: "简体中文",
            action: #selector(setLanguageZhHans(_:)),
            keyEquivalent: ""
        )
        zhItem.target = self
        zhItem.state = (currentLang == "zh-Hans") ? .on : .off
        langSubmenu.addItem(zhItem)

        let enItem = NSMenuItem(
            title: "English",
            action: #selector(setLanguageEn(_:)),
            keyEquivalent: ""
        )
        enItem.target = self
        enItem.state = (currentLang == "en") ? .on : .off
        langSubmenu.addItem(enItem)

        let langMenuItem = NSMenuItem(
            title: String(localized: "Language", locale: currentLocale),
            action: nil,
            keyEquivalent: ""
        )
        langMenuItem.submenu = langSubmenu
        menu.addItem(langMenuItem)

        let aboutItem = NSMenuItem(
            title: String(localized: "About GocryptKit", locale: currentLocale),
            action: #selector(openAboutPanel(_:)),
            keyEquivalent: ""
        )
        aboutItem.target = self
        menu.addItem(aboutItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(
            title: String(localized: "Quit GocryptKit", locale: currentLocale),
            action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: ""
        )
        quitItem.target = NSApp
        menu.addItem(quitItem)
    }

    // MARK: - Actions

    @objc func showMainWindow(_ sender: Any?) {
        appDelegate?.showMainWindow(sender)
    }

    @objc private func openAboutPanel(_ sender: Any?) {
        if let appDelegate = appDelegate {
            appDelegate.openAboutPanel(sender)
        } else {
            NSApp.activate(ignoringOtherApps: true)
            NSApp.orderFrontStandardAboutPanel(sender)
        }
    }

    @objc private func revealVaultInFinder(_ sender: NSMenuItem) {
        guard let path = sender.representedObject as? String else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    @objc private func focusVaultAction(_ sender: NSMenuItem) {
        guard let vaultID = sender.representedObject as? UUID else { return }
        appDelegate?.showAndFocusVault(id: vaultID)
    }

    @objc private func unmountVaultAction(_ sender: NSMenuItem) {
        guard let vault = sender.representedObject as? Vault else { return }
        guard !unmountingVaultIDs.contains(vault.id), !isUnmountingAll else { return }
        unmountingVaultIDs.insert(vault.id)
        performUnmount(vault: vault)
    }

    @objc private func unmountAllAction(_ sender: NSMenuItem) {
        guard !isUnmountingAll, unmountingVaultIDs.isEmpty else { return }
        isUnmountingAll = true
        performUnmountAll()
    }

    private func performUnmount(vault: Vault) {
        guard let mountPath = store.actualMountPoint(vault) ?? (store.isMounted(vault) ? vault.mountPointPath : nil) else {
            unmountingVaultIDs.remove(vault.id)
            return
        }
        let mountURL = URL(fileURLWithPath: mountPath)

        Task.detached(priority: .userInitiated) {
            do {
                try MountManager.shared.unmountVault(mountPoint: mountURL, force: false)
                await MainActor.run {
                    self.unmountingVaultIDs.remove(vault.id)
                    self.store.refreshMountState()
                    self.updateStatusIcon()
                }
            } catch {
                await MainActor.run {
                    self.unmountingVaultIDs.remove(vault.id)
                    self.handleUnmountError(error, vault: vault, mountURL: mountURL)
                }
            }
        }
    }

    private func performUnmountAll() {
        let mountedVaults = store.vaults.filter { store.isMounted($0) }
        guard !mountedVaults.isEmpty else {
            isUnmountingAll = false
            return
        }

        Task.detached(priority: .userInitiated) {
            var busyVaults: [(vault: Vault, mountURL: URL)] = []
            var failedVaults: [(vault: Vault, error: Error)] = []

            for vault in mountedVaults {
                guard let mountPath = await MainActor.run(body: { self.store.actualMountPoint(vault) }) ?? vault.mountPointPath as String? else { continue }
                let mountURL = URL(fileURLWithPath: mountPath)
                do {
                    try MountManager.shared.unmountVault(mountPoint: mountURL, force: false)
                } catch {
                    let desc = error.localizedDescription
                    if desc.contains("Resource busy") || desc.contains("EBUSY") {
                        busyVaults.append((vault, mountURL))
                    } else {
                        failedVaults.append((vault, error))
                    }
                }
            }

            await MainActor.run {
                self.isUnmountingAll = false
                self.store.refreshMountState()
                self.updateStatusIcon()

                if !busyVaults.isEmpty {
                    self.handleBatchBusyVaults(busyVaults)
                } else if let firstFail = failedVaults.first {
                    let alert = NSAlert()
                    alert.alertStyle = .warning
                    alert.messageText = String(localized: "Unmount Failed", locale: self.currentLocale)
                    alert.informativeText = firstFail.error.localizedDescription
                    NSApp.activate(ignoringOtherApps: true)
                    alert.runModal()
                }
            }
        }
    }

    @MainActor
    private func handleBatchBusyVaults(_ busyList: [(vault: Vault, mountURL: URL)]) {
        if busyList.count == 1 {
            let item = busyList[0]
            let err = NSError(domain: "Gocryptfs", code: Int(EBUSY), userInfo: [NSLocalizedDescriptionKey: "Resource busy"])
            handleUnmountError(err, vault: item.vault, mountURL: item.mountURL)
            return
        }

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = String(localized: "Volumes In Use", locale: currentLocale)
        let names = busyList.map { "「\($0.vault.name)」" }.joined(separator: "、")
        alert.informativeText = String(
            localized: "The following vaults are currently in use by other applications: \(names)\nPlease close related files or Finder windows and try again.",
            locale: currentLocale
        )
        alert.addButton(withTitle: String(localized: "Cancel", locale: currentLocale))
        alert.addButton(withTitle: String(localized: "Force Unmount All", locale: currentLocale))

        NSApp.activate(ignoringOtherApps: true)
        let response = alert.runModal()
        if response == .alertSecondButtonReturn {
            // User confirmed forced unmount all
            Task.detached(priority: .userInitiated) {
                var failedNames: [String] = []
                for item in busyList {
                    do {
                        try MountManager.shared.unmountVault(mountPoint: item.mountURL, force: true)
                    } catch {
                        failedNames.append(item.vault.name)
                    }
                }
                await MainActor.run {
                    self.store.refreshMountState()
                    self.updateStatusIcon()
                    if !failedNames.isEmpty {
                        let failAlert = NSAlert()
                        failAlert.alertStyle = .critical
                        failAlert.messageText = String(localized: "Force Unmount Failed", locale: self.currentLocale)
                        let joined = failedNames.joined(separator: ", ")
                        failAlert.informativeText = String(
                            localized: "Failed to force unmount: \(joined)",
                            locale: self.currentLocale
                        )
                        NSApp.activate(ignoringOtherApps: true)
                        failAlert.runModal()
                    }
                }
            }
        }
    }

    @MainActor
    private func handleUnmountError(_ error: Error, vault: Vault, mountURL: URL) {
        self.store.refreshMountState()
        self.updateStatusIcon()
        let errorDesc = error.localizedDescription

        if errorDesc.contains("Resource busy") || errorDesc.contains("EBUSY") {
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = String(localized: "Volume In Use", locale: currentLocale)
            alert.informativeText = String(
                localized: "Vault \"\(vault.name)\" is currently in use by another application. Please close related files or Finder windows and try again.",
                locale: currentLocale
            )
            alert.addButton(withTitle: String(localized: "Cancel", locale: currentLocale))
            alert.addButton(withTitle: String(localized: "Force Unmount", locale: currentLocale))

            NSApp.activate(ignoringOtherApps: true)
            let response = alert.runModal()
            if response == .alertSecondButtonReturn {
                // User chose force unmount
                Task.detached(priority: .userInitiated) {
                    do {
                        try MountManager.shared.unmountVault(mountPoint: mountURL, force: true)
                        await MainActor.run {
                            self.store.refreshMountState()
                            self.updateStatusIcon()
                        }
                    } catch {
                        await MainActor.run {
                            let failAlert = NSAlert()
                            failAlert.alertStyle = .critical
                            failAlert.messageText = String(localized: "Force Unmount Failed", locale: self.currentLocale)
                            failAlert.informativeText = error.localizedDescription
                            NSApp.activate(ignoringOtherApps: true)
                            failAlert.runModal()
                            self.store.refreshMountState()
                            self.updateStatusIcon()
                        }
                    }
                }
            }
        } else {
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = String(localized: "Unmount Failed", locale: currentLocale)
            alert.informativeText = errorDesc
            NSApp.activate(ignoringOtherApps: true)
            alert.runModal()
        }
    }

    @objc func setLanguageSystem(_ sender: Any?) {
        UserDefaults.standard.set("system", forKey: "appLanguage")
    }

    @objc func setLanguageZhHans(_ sender: Any?) {
        UserDefaults.standard.set("zh-Hans", forKey: "appLanguage")
    }

    @objc func setLanguageEn(_ sender: Any?) {
        UserDefaults.standard.set("en", forKey: "appLanguage")
    }
}
