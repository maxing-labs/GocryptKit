import AppKit

@main
@MainActor
struct GocryptKitApp {
    /// `NSApplication.delegate` is a weak reference; the delegate instance must be retained
    /// externally, otherwise ARC immediately deallocates it upon assignment.
    private static var appDelegate: AppDelegate?

    static func main() {
        let args = ProcessInfo.processInfo.arguments
        let cliCommands: Set<String> = ["init", "mount", "umount", "status", "version"]
        if args.count > 1 && cliCommands.contains(args[1]) {
            CLIRouter.runCLI(arguments: Array(args.dropFirst()))
        } else {
            LanguageManager.shared.syncStartupLanguage()
            let delegate = AppDelegate()
            appDelegate = delegate
            let app = NSApplication.shared
            app.delegate = delegate
            app.setActivationPolicy(.regular)
            app.activate(ignoringOtherApps: true)
            app.run()
        }
    }
}
