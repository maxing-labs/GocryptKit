import Foundation

/// The operational availability of the FSKit filesystem module from the kernel's perspective.
///
/// **Never rely on the `+` sign in `pluginkit` output.** That flag only indicates that
/// the extension is registered, which is completely decoupled from whether the kernel
/// is willing to activate and utilize the filesystem module:
///
/// - Built-in system modules like `exfat` / `msdos` do not even show a checkmark in `pluginkit`,
///   yet they operate normally.
/// - Conversely, this extension can have a `+` in `pluginkit`, but mounting will fail with:
///   `Module com.xwei.GocryptKit.AppEx is disabled!`
///
/// This discrepancy was the root cause of false-positive green status indicators prior to v0.2.0:
/// users saw "Enabled", but mounting consistently failed, with the error only surfacing at mount time.
public enum FSModuleStatus: String, Sendable, Equatable {
    /// The kernel recognizes and allows mounting via this module.
    case enabled
    /// Registered but disabled by system policy — the user needs to enable it in
    /// "System Settings → General → Login Items & Extensions → File System Extensions".
    case disabled
    /// The system has no record of this extension. Typically happens when the App
    /// has never been launched after installation (LaunchServices registers extensions on first launch).
    case notRegistered
    /// The probe failed or returned inconclusive output. Better to report unknown than falsely claim available.
    case unknown
}

/// Probes and interprets FSKit module status from command outputs.
///
/// Separated into pure functions for testability: toggling the module in the real system
/// cannot be easily automated, but captured CLI outputs can be fed directly into unit tests.
public enum FSModuleProbe {
    /// When the module is disabled, `mount` outputs this phrase verbatim to stderr.
    /// Case and punctuation match actual macOS kernel / FSKit output.
    static let disabledMarker = "is disabled"

    /// Determines whether the extension is present in `pluginkit -m -v -i <id>` output.
    ///
    /// Checks strictly for presence, ignoring the `+` indicator.
    public static func isRegistered(pluginkitOutput: String) -> Bool {
        pluginkitOutput.contains("(no matches)") == false
            && pluginkitOutput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
    }

    /// Interprets whether the module is disabled from the stderr of a deliberate `mount -t gocryptfs` probe.
    ///
    /// The classification is intentionally asymmetric: **only report disabled if the system explicitly says "disabled"**.
    /// All other outcomes are treated as enabled. Other failure modes exist on this probe path
    /// (e.g., cold start latency, invalid probe vault directory), and misclassifying them as "disabled"
    /// would wrongly prompt the user to check a System Settings toggle that is already enabled.
    public static func interpret(mountStderr: String) -> FSModuleStatus {
        mountStderr.contains(disabledMarker) ? .disabled : .enabled
    }
}
