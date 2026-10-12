import AppKit
import SwiftUI
import VaultCore
import OSLog

private let logger = Logger(subsystem: "com.xwei.GocryptKit", category: "AppDelegate")

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow?
    private(set) var vaultStore: VaultStore?
    private var menuBarManager: MenuBarManager?

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupMenu()
        let store = VaultStore()
        self.vaultStore = store
        let mb = MenuBarManager(appDelegate: self, store: store)
        mb.setupStatusItem()
        self.menuBarManager = mb

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleLanguageDidChange),
            name: .appLanguageDidChange,
            object: nil
        )

        let contentView = ContentView(store: store)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 420),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.center()
        window.title = "GocryptKit"
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: contentView)
        window.makeKeyAndOrderFront(nil)
        self.window = window

        // Defensively sweep any orphan credentials left in Keychain from previous crashes or unmounts
        MountManager.shared.reapOrphanCredentials()
    }

    @objc func showMainWindow(_ sender: Any?) {
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func showAndFocusVault(id: UUID) {
        showMainWindow(nil)
        vaultStore?.requestFocus(for: id)
    }

    @objc func openSettings(_ sender: Any?) {
        showMainWindow(sender)
    }

    @objc func openAboutPanel(_ sender: Any?) {
        NSApp.activate(ignoringOtherApps: true)
        let githubURL = URL(string: "https://github.com/maxing-labs/GocryptKit")!
        let pStyle = NSMutableParagraphStyle()
        pStyle.alignment = .center

        let credits = NSMutableAttributedString()
        let githubText = "GitHub: https://github.com/maxing-labs/GocryptKit"
        let attr = NSMutableAttributedString(
            string: githubText,
            attributes: [
                .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
                .foregroundColor: NSColor.secondaryLabelColor,
                .paragraphStyle: pStyle
            ]
        )
        let linkRange = (githubText as NSString).range(of: "https://github.com/maxing-labs/GocryptKit")
        attr.addAttribute(.link, value: githubURL, range: linkRange)
        attr.addAttribute(.foregroundColor, value: NSColor.linkColor, range: linkRange)
        attr.addAttribute(.underlineStyle, value: NSUnderlineStyle.single.rawValue, range: linkRange)
        credits.append(attr)

        NSApp.orderFrontStandardAboutPanel(options: [
            .credits: credits
        ])
    }

    @objc private func handleLanguageDidChange() {
        setupMenu()
    }

    private func setupMenu() {
        let mainMenu = NSMenu()

        // 1. App Menu
        let appMenuItem = NSMenuItem()
        let appMenu = NSMenu()
        let appName = "GocryptKit"

        let aboutItem = NSMenuItem(
            title: loc("About GocryptKit"),
            action: #selector(openAboutPanel(_:)),
            keyEquivalent: ""
        )
        aboutItem.target = self
        appMenu.addItem(aboutItem)

        let settingsItem = NSMenuItem(
            title: loc("Settings…"),
            action: #selector(openSettings(_:)),
            keyEquivalent: ","
        )
        settingsItem.target = self
        appMenu.addItem(settingsItem)
        appMenu.addItem(NSMenuItem.separator())

        let hideItem = NSMenuItem(
            title: loc("Hide \(appName)"),
            action: #selector(NSApplication.hide(_:)),
            keyEquivalent: "h"
        )
        appMenu.addItem(hideItem)

        let hideOthersItem = NSMenuItem(
            title: loc("Hide Others"),
            action: #selector(NSApplication.hideOtherApplications(_:)),
            keyEquivalent: "h"
        )
        hideOthersItem.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(hideOthersItem)

        let showAllItem = NSMenuItem(
            title: loc("Show All"),
            action: #selector(NSApplication.unhideAllApplications(_:)),
            keyEquivalent: ""
        )
        appMenu.addItem(showAllItem)
        appMenu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(
            title: loc("Quit \(appName)"),
            action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: "q"
        )
        appMenu.addItem(quitItem)
        appMenuItem.submenu = appMenu
        mainMenu.addItem(appMenuItem)

        // 2. File Menu
        let fileMenuItem = NSMenuItem()
        let fileMenu = NSMenu(title: loc("File"))
        let newItem = NSMenuItem(
            title: loc("Create New Vault…"),
            action: #selector(showMainWindow(_:)),
            keyEquivalent: "n"
        )
        newItem.target = self
        fileMenu.addItem(newItem)

        let openItem = NSMenuItem(
            title: loc("Add Existing Vault…"),
            action: #selector(showMainWindow(_:)),
            keyEquivalent: "o"
        )
        openItem.target = self
        fileMenu.addItem(openItem)

        fileMenu.addItem(NSMenuItem.separator())
        let closeItem = NSMenuItem(
            title: loc("Close Window"),
            action: #selector(NSWindow.performClose(_:)),
            keyEquivalent: "w"
        )
        fileMenu.addItem(closeItem)
        fileMenuItem.submenu = fileMenu
        mainMenu.addItem(fileMenuItem)

        // 3. Edit Menu (for Copy, Paste, Select All, Undo, Redo in TextFields)
        let editMenuItem = NSMenuItem()
        let editMenu = NSMenu(title: loc("Edit"))
        editMenu.addItem(withTitle: loc("Undo"), action: Selector(("undo:")), keyEquivalent: "z")
        let redoItem = NSMenuItem(title: loc("Redo"), action: Selector(("redo:")), keyEquivalent: "Z")
        editMenu.addItem(redoItem)
        editMenu.addItem(NSMenuItem.separator())
        editMenu.addItem(withTitle: loc("Cut"), action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: loc("Copy"), action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: loc("Paste"), action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: loc("Select All"), action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editMenuItem.submenu = editMenu
        mainMenu.addItem(editMenuItem)

        // 4. Window Menu
        let windowMenuItem = NSMenuItem()
        let windowMenu = NSMenu(title: loc("Window"))
        windowMenu.addItem(withTitle: loc("Minimize"), action: #selector(NSWindow.miniaturize(_:)), keyEquivalent: "m")
        windowMenu.addItem(withTitle: loc("Zoom"), action: #selector(NSWindow.zoom(_:)), keyEquivalent: "")
        windowMenu.addItem(NSMenuItem.separator())
        windowMenu.addItem(withTitle: loc("Close"), action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        windowMenuItem.submenu = windowMenu
        mainMenu.addItem(windowMenuItem)

        NSApp.mainMenu = mainMenu
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            showMainWindow(nil)
        }
        return true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // Only this user's volumes: another account's mounts are not ours to take down.
        let mounts = Array(MountTable.gocryptfsMounts(ownedBy: getuid()).values)
        guard !mounts.isEmpty else {
            return .terminateNow
        }

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = loc("Unmount before quitting?")
        let count = mounts.count
        if count == 1 {
            alert.informativeText = loc("There is 1 mounted vault. Quitting GocryptKit will unmount it. Do you want to continue?")
        } else {
            alert.informativeText = loc("There are \(count) mounted vaults. Quitting GocryptKit will unmount all of them. Do you want to continue?")
        }
        alert.addButton(withTitle: loc("Unmount and Quit"))
        alert.addButton(withTitle: loc("Cancel"))

        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else {
            return .terminateCancel
        }
        // umount can block for seconds per volume; keep it off the main thread
        // and answer the termination request once the outcome is known.
        unmountForQuit(mounts, force: false)
        return .terminateLater
    }

    func applicationWillTerminate(_ notification: Notification) {
        // No unmounting here: applicationShouldTerminate only lets the app quit
        // once this user's volumes are gone, and a last-moment `umount -f`
        // would truncate files that are still being written.
        MountManager.shared.reapOrphanCredentials()
    }

    private func unmountForQuit(_ mounts: [MountTable.Entry], force: Bool) {
        Task.detached(priority: .userInitiated) {
            let outcome = QuitUnmount.attempt(mounts, force: force) { entry, force in
                try MountManager.shared.unmountVault(mountPoint: URL(fileURLWithPath: entry.mountPoint), force: force)
                _ = KeychainStore.deleteCredential(account: Vault.canonicalKey(path: entry.sourcePath))
            }.settled(stillMounted: Array(MountTable.gocryptfsMounts(ownedBy: getuid()).values))
            await MainActor.run {
                self.finishQuit(outcome, forced: force)
            }
        }
    }

    private func finishQuit(_ outcome: QuitUnmount.Outcome, forced: Bool) {
        vaultStore?.refreshMountState()
        if outcome.allUnmounted {
            NSApp.reply(toApplicationShouldTerminate: true)
            return
        }

        // A volume is still mounted: stay running. Force only on explicit confirmation,
        // with the same dialog the other unmount entry points use.
        let alert = NSAlert()
        NSApp.activate(ignoringOtherApps: true)
        if !forced && outcome.canQuitByForcing {
            alert.alertStyle = .warning
            if outcome.busy.count == 1 {
                alert.messageText = loc("Volume In Use")
                alert.informativeText = loc("Vault \"\(displayName(of: outcome.busy[0]))\" is currently in use by another application. Please close related files or Finder windows and try again.")
                alert.addButton(withTitle: loc("Cancel"))
                alert.addButton(withTitle: loc("Force Unmount"))
            } else {
                alert.messageText = loc("Volumes In Use")
                let names = outcome.busy.map { "「\(displayName(of: $0))」" }.joined(separator: "、")
                alert.informativeText = loc("The following vaults are currently in use by other applications: \(names)\nPlease close related files or Finder windows and try again.")
                alert.addButton(withTitle: loc("Cancel"))
                alert.addButton(withTitle: loc("Force Unmount All"))
            }
            if alert.runModal() == .alertSecondButtonReturn {
                unmountForQuit(outcome.busy, force: true)
                return
            }
        } else {
            alert.alertStyle = .critical
            alert.messageText = forced ? loc("Force Unmount Failed") : loc("Unmount Failed")
            alert.informativeText = (outcome.busy + outcome.failed).map { displayName(of: $0) }.joined(separator: ", ")
            alert.runModal()
        }
        NSApp.reply(toApplicationShouldTerminate: false)
    }

    private func displayName(of entry: MountTable.Entry) -> String {
        let key = Vault.canonicalKey(path: entry.sourcePath)
        if let vault = vaultStore?.vaults.first(where: { Vault.canonicalKey(path: $0.cipherDirPath) == key }) {
            return vault.name
        }
        return URL(fileURLWithPath: entry.mountPoint).lastPathComponent
    }
}
