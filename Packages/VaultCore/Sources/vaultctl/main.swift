import Foundation
import VaultCore

func printUsage() {
    print("""
    Usage: vaultctl <command> -p <password> [options]

    Commands:
      init <cipherDir> -p <password> [--scryptn <logN>]
          Create a new gocryptfs vault in an existing empty directory
      ls <cipherDir> -p <password> [plainDir]
          List files in directory
      cat <cipherDir> -p <password> <plainFilePath>
          Read and print file contents
      readlink <cipherDir> -p <password> <plainSymlinkPath>
          Print symlink target
      verify <cipherDir> -p <password>
          Verify against gold standard (status.txt, rel, abs)

    -p is mandatory. There is no default password.
    --scryptn lowers the scrypt cost for tests; it weakens the vault.
    """)
}

/// Extracts `-p <password>` and `--scryptn <logN>` from arguments, returning the rest unmodified.
///
/// Passwords have no default value: missing `-p` returns nil, and the caller rejects execution.
/// Historically, this defaulted to `"test"`, while all fixtures happened to use `"test"` as well —
/// causing "wrong password" and "correct password" paths to appear deceptively identical.
func parseOptions(args: [String]) -> (password: String?, scryptLogN: Int32, remaining: [String]) {
    var password: String? = nil
    var scryptLogN = GocryptfsEngine.defaultScryptLogN
    var remaining: [String] = []
    var i = 0
    while i < args.count {
        if args[i] == "-p" && i + 1 < args.count {
            password = args[i + 1]
            i += 2
        } else if args[i] == "--scryptn" && i + 1 < args.count {
            scryptLogN = Int32(args[i + 1]) ?? -1
            i += 2
        } else {
            remaining.append(args[i])
            i += 1
        }
    }
    return (password, scryptLogN, remaining)
}

func main() {
    let args = Array(CommandLine.arguments.dropFirst())
    guard !args.isEmpty else {
        printUsage()
        exit(1)
    }

    let command = args[0]
    let subArgs = Array(args.dropFirst())
    let (maybePassword, scryptLogN, remaining) = parseOptions(args: subArgs)

    guard !remaining.isEmpty else {
        print("Error: missing cipherDir")
        printUsage()
        exit(1)
    }
    guard let password = maybePassword, !password.isEmpty else {
        fputs("Error: missing -p <password>. Refusing to guess a vault password.\n", stderr)
        exit(1)
    }

    let cipherDir = URL(fileURLWithPath: remaining[0])

    // `init` must run before the vault exists, so it cannot follow the "open vault first" path below.
    if command == "init" {
        do {
            _ = try GocryptfsEngine.createVault(at: cipherDir, password: password, scryptLogN: scryptLogN)
            print("Created vault at \(cipherDir.path)")
            print("There is no way to recover this vault if the password is lost.")
            exit(0)
        } catch {
            fputs("Error: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }

    do {
        let engine = try GocryptfsEngine(cipherDir: cipherDir, credential: .password(password))
        defer { engine.shutdown() }

        switch command {
        case "ls":
            let plainDir = remaining.count > 1 ? remaining[1] : "/"
            let entries = try engine.list(plainDir)
            for entry in entries.sorted(by: { $0.name < $1.name }) {
                let typeStr: String
                if entry.isDirectory { typeStr = "d" }
                else if entry.isSymlink { typeStr = "l" }
                else { typeStr = "f" }
                print(String(format: "%@  %6o  %@", typeStr, entry.mode & 0o7777, entry.name))
            }

        case "cat":
            guard remaining.count > 1 else {
                print("Error: missing plainFilePath")
                exit(1)
            }
            let filePath = remaining[1]
            let handle = try engine.open(filePath)
            defer { engine.close(handle) }

            var buffer = [UInt8](repeating: 0, count: 64 * 1024)
            var offset: UInt64 = 0
            while true {
                let n = try buffer.withUnsafeMutableBytes {
                    try engine.read(handle, offset: offset, into: $0)
                }
                if n == 0 { break }
                let chunk = Data(buffer[0..<n])
                FileHandle.standardOutput.write(chunk)
                offset += UInt64(n)
            }

        case "readlink":
            guard remaining.count > 1 else {
                print("Error: missing plainSymlinkPath")
                exit(1)
            }
            let linkPath = remaining[1]
            let target = try engine.readlink(linkPath)
            print(target)

        case "verify":
            print("Verifying vault: \(cipherDir.path)")
            let entries = try engine.list("/")
            print("[PASS] list root: found \(entries.count) entries")

            // Check status.txt
            let handle = try engine.open("status.txt")
            var buf = [UInt8](repeating: 0, count: 256)
            let readBytes = try buf.withUnsafeMutableBytes {
                try engine.read(handle, offset: 0, into: $0)
            }
            engine.close(handle)
            let statusText = String(decoding: buf[0..<readBytes], as: UTF8.self)
            if statusText == "It works!\n" || statusText == "It works!" {
                print("[PASS] read status.txt: \"\(statusText.trimmingCharacters(in: .whitespacesAndNewlines))\"")
            } else {
                print("[FAIL] read status.txt unexpected content: \(statusText)")
                exit(1)
            }

            // Check rel symlink
            if let targetRel = try? engine.readlink("rel") {
                if targetRel == "status.txt" {
                    print("[PASS] readlink rel -> \(targetRel)")
                } else {
                    print("[FAIL] readlink rel -> expected status.txt, got \(targetRel)")
                    exit(1)
                }
            } else {
                print("[WARN] rel symlink not found in vault")
            }

            // Check abs symlink
            if let targetAbs = try? engine.readlink("abs") {
                if targetAbs == "/a/b/c/d" {
                    print("[PASS] readlink abs -> \(targetAbs)")
                } else {
                    print("[FAIL] readlink abs -> expected /a/b/c/d, got \(targetAbs)")
                    exit(1)
                }
            } else {
                print("[WARN] abs symlink not found in vault")
            }

            // Check cipherPath
            if let cPath = engine.cipherPath("status.txt") {
                print("[PASS] cipherPath status.txt -> \(cPath)")
            } else {
                print("[FAIL] cipherPath status.txt failed")
                exit(1)
            }

            print("[ALL VERIFICATIONS PASSED]")

        default:
            print("Unknown command: \(command)")
            printUsage()
            exit(1)
        }
    } catch {
        print("Error: \(error.localizedDescription)")
        exit(1)
    }
}

main()
