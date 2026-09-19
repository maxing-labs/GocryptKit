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
        MountManager.shared.reapOrphanCredentials(knownVaults: store.vaults)
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
            title: "Hide \(appName)",
            action: #selector(NSApplication.hide(_:)),
            keyEquivalent: "h"
        )
        appMenu.addItem(hideItem)

        let hideOthersItem = NSMenuItem(
            title: "Hide Others",
            action: #selector(NSApplication.hideOtherApplications(_:)),
            keyEquivalent: "h"
        )
        hideOthersItem.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(hideOthersItem)

        let showAllItem = NSMenuItem(
            title: "Show All",
            action: #selector(NSApplication.unhideAllApplications(_:)),
            keyEquivalent: ""
        )
        appMenu.addItem(showAllItem)
        appMenu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(
            title: "Quit \(appName)",
            action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: "q"
        )
        appMenu.addItem(quitItem)
        appMenuItem.submenu = appMenu
        mainMenu.addItem(appMenuItem)

        // 2. File Menu
        let fileMenuItem = NSMenuItem()
        let fileMenu = NSMenu(title: "File")
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
        let editMenu = NSMenu(title: "Edit")
        editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        let redoItem = NSMenuItem(title: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        editMenu.addItem(redoItem)
        editMenu.addItem(NSMenuItem.separator())
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editMenuItem.submenu = editMenu
        mainMenu.addItem(editMenuItem)

        // 3. Window Menu
        let windowMenuItem = NSMenuItem()
        let windowMenu = NSMenu(title: "Window")
        windowMenu.addItem(withTitle: "Minimize", action: #selector(NSWindow.miniaturize(_:)), keyEquivalent: "m")
        windowMenu.addItem(withTitle: "Zoom", action: #selector(NSWindow.zoom(_:)), keyEquivalent: "")
        windowMenu.addItem(NSMenuItem.separator())
        windowMenu.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
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
        let mounts = MountTable.gocryptfsMounts()
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
        let response = alert.runModal()
        if response == .alertFirstButtonReturn {
            unmountAllMountedVaults(mounts: mounts)
            return .terminateNow
        } else {
            return .terminateCancel
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        let remaining = MountTable.gocryptfsMounts()
        if !remaining.isEmpty {
            unmountAllMountedVaults(mounts: remaining)
        }
        MountManager.shared.reapOrphanCredentials(knownVaults: vaultStore?.vaults ?? [])
    }

    private func unmountAllMountedVaults(mounts: [String: MountTable.Entry]) {
        for (_, entry) in mounts {
            let url = URL(fileURLWithPath: entry.mountPoint)
            do {
                try MountManager.shared.unmountVault(mountPoint: url)
            } catch {
                logger.error("Failed to unmount \(entry.mountPoint): \(error.localizedDescription), trying force unmount")
                do {
                    try MountManager.shared.unmountVault(mountPoint: url, force: true)
                } catch {
                    logger.error("Force unmount also failed for \(entry.mountPoint): \(error.localizedDescription)")
                }
            }
            _ = KeychainStore.deleteCredential(account: Vault.canonicalKey(path: entry.sourcePath))
        }
    }
}
