import Foundation
import VaultCore

enum CLIRouter {
    /// Read a password interactively from the terminal with echo disabled.
    /// Returns nil if stdin is not a terminal or the read fails.
    private static func readPassword(prompt: String, confirm: Bool = false) -> String? {
        guard isatty(STDIN_FILENO) != 0 else {
            fputs("Error: stdin is not a terminal. Cannot read password interactively.\n", stderr)
            return nil
        }
        var buf = [CChar](repeating: 0, count: 1024)
        guard let result = readpassphrase(prompt, &buf, buf.count, RPP_REQUIRE_TTY) else {
            return nil
        }
        let password = String(cString: result)
        // Securely zero the buffer after reading
        memset_s(&buf, buf.count, 0, buf.count)
        
        if confirm {
            var buf2 = [CChar](repeating: 0, count: 1024)
            guard let result2 = readpassphrase("Confirm password: ", &buf2, buf2.count, RPP_REQUIRE_TTY) else {
                return nil
            }
            let confirmed = String(cString: result2)
            memset_s(&buf2, buf2.count, 0, buf2.count)
            guard password == confirmed else {
                fputs("Passwords do not match.\n", stderr)
                return nil
            }
        }
        
        return password.isEmpty ? nil : password
    }

    /// Read a password from standard input (pipeline/script automation).
    /// Strips trailing newlines to accommodate `echo` or `printf`.
    /// Caps input at 4 KiB to prevent denial-of-service / OOM via unbounded streams.
    private static func readPasswordStdin() -> String? {
        let handle = FileHandle.standardInput
        let maxPasswordBytes = 4096
        let inputData = handle.readData(ofLength: maxPasswordBytes)
        guard !inputData.isEmpty, let text = String(data: inputData, encoding: .utf8) else {
            return nil
        }
        let trimmed = text.trimmingCharacters(in: .newlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    static func runCLI(arguments: [String]) {
        let command = arguments[0]
        switch command {
        case "init":
            guard arguments.count >= 2 else {
                print("Usage: GocryptKit init <cipherDir> [--scryptn <logN>] [--password-stdin]")
                exit(1)
            }
            let cipherPath = (arguments[1] as NSString).expandingTildeInPath
            var isDirInit: ObjCBool = false
            if FileManager.default.fileExists(atPath: cipherPath, isDirectory: &isDirInit) {
                guard isDirInit.boolValue else {
                    fputs("Error: '\(cipherPath)' is not a directory.\n", stderr)
                    exit(1)
                }
            } else {
                do {
                    try FileManager.default.createDirectory(atPath: cipherPath, withIntermediateDirectories: true)
                } catch {
                    fputs("Error creating directory '\(cipherPath)': \(error.localizedDescription)\n", stderr)
                    exit(1)
                }
            }
            // Reject the insecure --password flag
            if arguments.contains("--password") {
                fputs("Error: --password has been removed for security reasons.\nPasswords are now entered interactively (no echo) or passed via --password-stdin.\n", stderr)
                exit(1)
            }
            let password: String?
            if arguments.contains("--password-stdin") {
                password = readPasswordStdin()
                if password == nil {
                    fputs("Failed to read password from stdin.\n", stderr)
                    exit(1)
                }
            } else {
                password = readPassword(prompt: "New vault password: ", confirm: true)
                if password == nil {
                    fputs("Failed to read password. Make sure you are running in a terminal.\n", stderr)
                    exit(1)
                }
            }
            guard let validPassword = password, !validPassword.isEmpty else {
                fputs("Password cannot be empty.\n", stderr)
                exit(1)
            }
            // --scryptn exists exclusively for testing (default logN=16 takes 1-2 seconds per derivation).
            // Lowering it weakens password security; do not pass it during normal operation.
            var scryptLogN = GocryptfsEngine.defaultScryptLogN
            if let raw = value(of: "--scryptn", in: arguments) {
                guard let parsed = Int32(raw) else {
                    fputs("--scryptn expects an integer.\n", stderr)
                    exit(1)
                }
                scryptLogN = parsed
            }

            do {
                _ = try GocryptfsEngine.createVault(
                    at: URL(fileURLWithPath: cipherPath),
                    password: validPassword,
                    scryptLogN: scryptLogN
                )
                print("Created vault at \(cipherPath)")
                print("If this password is lost the contents cannot be recovered.")
                exit(0)
            } catch {
                fputs("Init error: \(error.localizedDescription)\n", stderr)
                exit(1)
            }

        case "mount":
            guard arguments.count >= 3 else {
                print("Usage: GocryptKit mount <cipherDir> <mountPoint> [--password-stdin]")
                exit(1)
            }
            let cipherPath = (arguments[1] as NSString).expandingTildeInPath
            let mountPath = (arguments[2] as NSString).expandingTildeInPath
            var isDirMount: ObjCBool = false
            guard FileManager.default.fileExists(atPath: cipherPath, isDirectory: &isDirMount), isDirMount.boolValue else {
                fputs("Error: cipher directory '\(cipherPath)' does not exist or is not a directory.\n", stderr)
                exit(1)
            }
            // Reject the insecure --password flag
            if arguments.contains("--password") {
                fputs("Error: --password has been removed for security reasons.\nPasswords are now entered interactively (no echo) or passed via --password-stdin.\n", stderr)
                exit(1)
            }
            let password: String?
            if arguments.contains("--password-stdin") {
                password = readPasswordStdin()
                if password == nil {
                    fputs("Failed to read password from stdin.\n", stderr)
                    exit(1)
                }
            } else {
                password = readPassword(prompt: "Vault password: ")
                if password == nil {
                    fputs("Failed to read password. Make sure you are running in a terminal.\n", stderr)
                    exit(1)
                }
            }
            guard let validPassword = password, !validPassword.isEmpty else {
                fputs("Password cannot be empty.\n", stderr)
                exit(1)
            }

            do {
                try MountManager.shared.mountVaultSync(
                    cipherDir: URL(fileURLWithPath: cipherPath),
                    mountPoint: URL(fileURLWithPath: mountPath),
                    password: validPassword
                )
                print("Successfully mounted \(cipherPath) on \(mountPath)")
                exit(0)
            } catch {
                fputs("Mount error: \(error.localizedDescription)\n", stderr)
                exit(1)
            }

        case "umount":
            guard arguments.count >= 2 else {
                print("Usage: GocryptKit umount <mountPoint>")
                exit(1)
            }
            let mountPath = (arguments[1] as NSString).expandingTildeInPath
            do {
                try MountManager.shared.unmountVault(mountPoint: URL(fileURLWithPath: mountPath))
                print("Successfully unmounted \(mountPath)")
                exit(0)
            } catch {
                fputs("Unmount error: \(error.localizedDescription)\n", stderr)
                exit(1)
            }

        case "status":
            MountManager.shared.checkExtensionStatus()
            // Note that "DISABLED" does not contain the substring "ENABLED", so e2e's `grep -q ENABLED`
            // still only matches when genuinely enabled. Review Tests/e2e/run-e2e.sh:122 before modifying these lines.
            switch MountManager.shared.extensionStatus {
            case .enabled:
                print("GocryptKit Extension Status: ENABLED")
                exit(0)
            case .disabled:
                print("GocryptKit Extension Status: DISABLED")
                print("The module is registered but disabled by the system. To enable it:")
                print("  System Settings → General → Login Items & Extensions → scroll to bottom 'File System Extensions' → Enable GocryptKit")
                exit(2)
            case .notRegistered:
                print("GocryptKit Extension Status: NOT REGISTERED")
                print("The system has not recognized this extension yet. Launch GocryptKit.app once, then enable it in System Settings.")
                exit(3)
            case .unknown:
                print("GocryptKit Extension Status: UNKNOWN")
                print("Probe failed; unable to determine module availability.")
                exit(4)
            }

        case "version":
            let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
            let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown"
            print("GocryptKit \(version) (build \(build))")
            exit(0)

        default:
            print("Unknown command: \(command)")
            print("Available commands: init, mount, umount, status, version")
            exit(1)
        }
    }

    private static func value(of flag: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: flag), index + 1 < arguments.count else {
            return nil
        }
        return arguments[index + 1]
    }
}
