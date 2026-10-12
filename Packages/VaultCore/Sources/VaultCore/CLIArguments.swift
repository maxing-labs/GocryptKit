import Foundation

/// A fully parsed command line. Parsing is strict: an option that is not
/// recognised is an error, never ignored. Silently dropping a misspelled
/// `--readonly` would mount a vault writable.
public enum CLICommand: Equatable, Sendable {
    case initVault(cipherDir: String, scryptLogN: Int32?, passwordFromStdin: Bool)
    case mount(cipherDir: String, mountPoint: String, readOnly: Bool, passwordFromStdin: Bool)
    case unmount(mountPoint: String, force: Bool)
    case status
    case version
}

public struct CLIUsageError: LocalizedError, Equatable, Sendable {
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var errorDescription: String? { message }
}

public enum CLIArguments {
    public static let commands: Set<String> = ["init", "mount", "umount", "status", "version"]

    static let initUsage = "Usage: GocryptKit init <cipherDir> [--scryptn <logN>] [--password-stdin]"
    static let mountUsage = "Usage: GocryptKit mount <cipherDir> <mountPoint> [--readonly|-r] [--password-stdin]"
    static let unmountUsage = "Usage: GocryptKit umount <mountPoint> [-f|--force]"

    /// Parses `arguments` (the command name first, without the executable path).
    public static func parse(_ arguments: [String]) throws -> CLICommand {
        guard let command = arguments.first else {
            throw CLIUsageError("Available commands: init, mount, umount, status, version")
        }
        let rest = Array(arguments.dropFirst())
        switch command {
        case "init":
            let parsed = try scan(rest, flags: ["--password-stdin"], valued: ["--scryptn"], usage: initUsage)
            guard parsed.positional.count == 1 else { throw CLIUsageError(initUsage) }
            var logN: Int32?
            if let raw = parsed.values["--scryptn"] {
                guard let value = Int32(raw) else { throw CLIUsageError("--scryptn expects an integer.") }
                logN = value
            }
            return .initVault(cipherDir: parsed.positional[0], scryptLogN: logN,
                              passwordFromStdin: parsed.flags.contains("--password-stdin"))
        case "mount":
            let parsed = try scan(rest, flags: ["--password-stdin", "--readonly", "-r", "--ro"], valued: [], usage: mountUsage)
            guard parsed.positional.count == 2 else { throw CLIUsageError(mountUsage) }
            let readOnly = !parsed.flags.isDisjoint(with: ["--readonly", "-r", "--ro"])
            return .mount(cipherDir: parsed.positional[0], mountPoint: parsed.positional[1], readOnly: readOnly,
                          passwordFromStdin: parsed.flags.contains("--password-stdin"))
        case "umount":
            let parsed = try scan(rest, flags: ["-f", "--force"], valued: [], usage: unmountUsage)
            guard parsed.positional.count == 1 else { throw CLIUsageError(unmountUsage) }
            return .unmount(mountPoint: parsed.positional[0], force: !parsed.flags.isEmpty)
        case "status", "version":
            guard rest.isEmpty else { throw CLIUsageError("'\(command)' takes no arguments.") }
            return command == "status" ? .status : .version
        default:
            throw CLIUsageError("Unknown command: \(command)\nAvailable commands: init, mount, umount, status, version")
        }
    }

    private struct Scanned {
        var positional: [String] = []
        var flags: Set<String> = []
        var values: [String: String] = [:]
    }

    private static func scan(_ arguments: [String], flags: Set<String>, valued: Set<String>, usage: String) throws -> Scanned {
        var result = Scanned()
        var index = 0
        var onlyPositional = false
        while index < arguments.count {
            let argument = arguments[index]
            index += 1
            if onlyPositional || !argument.hasPrefix("-") || argument == "-" {
                result.positional.append(argument)
            } else if argument == "--" {
                onlyPositional = true  // lets a path that starts with "-" through
            } else if argument == "--password" || argument.hasPrefix("--password=") {
                throw CLIUsageError("--password has been removed for security reasons.\nPasswords are now entered interactively (no echo) or passed via --password-stdin.")
            } else if flags.contains(argument) {
                result.flags.insert(argument)
            } else if valued.contains(argument) {
                guard index < arguments.count else { throw CLIUsageError("\(argument) expects a value.\n\(usage)") }
                result.values[argument] = arguments[index]
                index += 1
            } else {
                // Name only: the value of `--name=value` may be a password.
                let name = argument.split(separator: "=", maxSplits: 1).first.map(String.init) ?? argument
                throw CLIUsageError("Unknown option: \(name)\n\(usage)")
            }
        }
        return result
    }
}

/// Password handed over on standard input (`--password-stdin`).
public enum StdinPassword {
    /// Longest accepted password in bytes. A longer one is rejected: truncating it
    /// would create or open a vault with a different password than the caller sent.
    public static let maximumBytes = 4096
    /// Read this many bytes so that an over-long password is detectable.
    public static let readLimit = maximumBytes + 2

    public enum Failure: LocalizedError, Equatable {
        case empty
        case tooLong
        case notUTF8
        case terminal

        public var errorDescription: String? {
            switch self {
            case .empty:
                return "No password on stdin."
            case .tooLong:
                return "The password on stdin is longer than \(StdinPassword.maximumBytes) bytes; refusing to truncate it."
            case .notUTF8:
                return "The password on stdin is not valid UTF-8."
            case .terminal:
                return "stdin is a terminal, so --password-stdin would echo the password. Omit --password-stdin to be prompted without echo."
            }
        }
    }

    /// Exactly one trailing newline belongs to the pipe (`echo`, `printf '%s\n'`).
    /// Every other byte, further newlines included, is part of the password.
    public static func parse(_ input: Data) throws -> String {
        var bytes = input
        if bytes.last == UInt8(ascii: "\n") {
            bytes.removeLast()
        }
        guard !bytes.isEmpty else { throw Failure.empty }
        guard bytes.count <= maximumBytes else { throw Failure.tooLong }
        guard let password = String(data: bytes, encoding: .utf8) else { throw Failure.notUTF8 }
        return password
    }
}
