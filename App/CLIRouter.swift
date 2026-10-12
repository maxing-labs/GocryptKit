import Foundation
import VaultCore

/// Write end of the self-pipe the signal handler uses; see `removeCredentialOnInterrupt`.
nonisolated(unsafe) private var interruptPipeWriteEnd: Int32 = -1

enum CLIRouter {
    /// Read a password interactively from the terminal with echo disabled.
    /// Returns nil if stdin is not a terminal or the read fails.
    private static func readPassword(prompt: String, confirm: Bool = false) -> String? {
        guard isatty(STDIN_FILENO) != 0 else {
            fputs("Error: stdin is not a terminal. Cannot read password interactively.\n", stderr)
            return nil
        }
        // One byte more than the limit, so an over-long entry is detected instead of truncated.
        let capacity = StdinPassword.maximumBytes + 2
        var buf = [CChar](repeating: 0, count: capacity)
        guard let result = readpassphrase(prompt, &buf, buf.count, RPP_REQUIRE_TTY) else {
            return nil
        }
        let password = String(cString: result)
        // Securely zero the buffer after reading
        memset_s(&buf, buf.count, 0, buf.count)
        guard password.utf8.count <= StdinPassword.maximumBytes else {
            fputs("Error: \(StdinPassword.Failure.tooLong.localizedDescription)\n", stderr)
            return nil
        }

        if confirm {
            var buf2 = [CChar](repeating: 0, count: capacity)
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
    /// See `StdinPassword` for what is stripped and what is rejected.
    private static func readPasswordStdin() throws -> String {
        // On a terminal the line discipline would echo the password as it is typed.
        guard isatty(STDIN_FILENO) == 0 else {
            throw StdinPassword.Failure.terminal
        }
        return try StdinPassword.parse(FileHandle.standardInput.readData(ofLength: StdinPassword.readLimit))
    }

    private static func obtainPassword(fromStdin: Bool, prompt: String, confirm: Bool) -> String {
        if fromStdin {
            do {
                return try readPasswordStdin()
            } catch {
                fputs("Failed to read password from stdin: \(error.localizedDescription)\n", stderr)
                exit(1)
            }
        }
        guard let password = readPassword(prompt: prompt, confirm: confirm), !password.isEmpty else {
            fputs("Failed to read password. Make sure you are running in a terminal.\n", stderr)
            exit(1)
        }
        return password
    }

    /// A mount holds the vault credential in the Keychain until the extension
    /// consumes it. If the user interrupts the mount in that window (Ctrl-C),
    /// remove the credential instead of leaving it behind.
    ///
    /// Handlers rather than SIG_IGN: handlers reset to the default across exec, so
    /// `/sbin/mount` still dies from the terminal's Ctrl-C. The handler itself only
    /// writes to a pipe (async-signal-safe); a thread does the Keychain work.
    private static func removeCredentialOnInterrupt(cipherPath: String) {
        var fds: [Int32] = [0, 0]
        guard pipe(&fds) == 0 else { return }
        interruptPipeWriteEnd = fds[1]
        let readEnd = fds[0]
        let account = Vault.canonicalKey(path: cipherPath)
        Thread.detachNewThread {
            var caught: UInt8 = 0
            guard read(readEnd, &caught, 1) == 1 else { return }
            ProcessRunner.terminateActiveChild()
            _ = KeychainStore.deleteCredential(account: account)
            _ = MountContextStore.delete(for: cipherPath)
            fputs("\nInterrupted. The stored credential was removed.\n", stderr)
            exit(128 + Int32(caught))
        }
        for sig in [SIGINT, SIGTERM, SIGHUP] {
            signal(sig) { caught in
                var byte = UInt8(truncatingIfNeeded: caught)
                _ = write(interruptPipeWriteEnd, &byte, 1)
            }
        }
    }

    static func runCLI(arguments: [String]) {
        let command: CLICommand
        do {
            command = try CLIArguments.parse(arguments)
        } catch {
            fputs("Error: \(error.localizedDescription)\n", stderr)
            exit(1)
        }

        switch command {
        case .initVault(let rawCipherDir, let requestedLogN, let passwordFromStdin):
            let cipherPath = (rawCipherDir as NSString).expandingTildeInPath
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
            let password = obtainPassword(fromStdin: passwordFromStdin, prompt: "New vault password: ", confirm: true)
            // --scryptn exists exclusively for testing (default logN=16 takes 1-2 seconds per derivation).
            // Lowering it weakens password security; do not pass it during normal operation.
            let scryptLogN = requestedLogN ?? GocryptfsEngine.defaultScryptLogN

            do {
                _ = try GocryptfsEngine.createVault(
                    at: URL(fileURLWithPath: cipherPath),
                    password: password,
                    scryptLogN: scryptLogN
                )
                print("Created vault at \(cipherPath)")
                print("If this password is lost the contents cannot be recovered.")
                exit(0)
            } catch {
                fputs("Init error: \(error.localizedDescription)\n", stderr)
                exit(1)
            }

        case .mount(let rawCipherDir, let rawMountPoint, let readOnly, let passwordFromStdin):
            let cipherPath = (rawCipherDir as NSString).expandingTildeInPath
            let mountPath = (rawMountPoint as NSString).expandingTildeInPath
            var isDirMount: ObjCBool = false
            guard FileManager.default.fileExists(atPath: cipherPath, isDirectory: &isDirMount), isDirMount.boolValue else {
                fputs("Error: cipher directory '\(cipherPath)' does not exist or is not a directory.\n", stderr)
                exit(1)
            }
            let password = obtainPassword(fromStdin: passwordFromStdin, prompt: "Vault password: ", confirm: false)

            removeCredentialOnInterrupt(cipherPath: cipherPath)
            do {
                try MountManager.shared.mountVaultSync(
                    cipherDir: URL(fileURLWithPath: cipherPath),
                    mountPoint: URL(fileURLWithPath: mountPath),
                    password: password,
                    readOnly: readOnly
                )
                print("Successfully mounted \(cipherPath) on \(mountPath)\(readOnly ? " (read-only)" : "")")
                if MountPointSecurity.isReachableByOthers(URL(fileURLWithPath: mountPath).deletingLastPathComponent()) {
                    fputs("Warning: other users of this Mac can reach \(mountPath). Mounted files are readable by anyone who can get there.\n", stderr)
                }
                exit(0)
            } catch {
                fputs("Mount error: \(error.localizedDescription)\n", stderr)
                exit(1)
            }

        case .unmount(let rawMountPoint, let force):
            let mountPath = (rawMountPoint as NSString).expandingTildeInPath
            do {
                try MountManager.shared.unmountVault(mountPoint: URL(fileURLWithPath: mountPath), force: force)
                print("Successfully unmounted \(mountPath)")
                exit(0)
            } catch {
                fputs("Unmount error: \(error.localizedDescription)\n", stderr)
                exit(1)
            }

        case .status:
            MountManager.shared.checkExtensionStatus()
            // Note that "DISABLED" does not contain the substring "ENABLED", so e2e's `grep -q ENABLED`
            // still only matches when genuinely enabled. Review Tests/e2e/run-e2e.sh:122 before modifying these lines.
            let status = MainActor.assumeIsolated { MountManager.shared.extensionStatus }
            switch status {
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

        case .version:
            let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
            let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown"
            print("GocryptKit \(version) (build \(build))")
            exit(0)
        }
    }
}
