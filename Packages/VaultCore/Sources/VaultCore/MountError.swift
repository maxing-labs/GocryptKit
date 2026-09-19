import Foundation

/// Strongly-typed error classifications for filesystem mount operations.
public enum MountError: LocalizedError, Sendable, Equatable {
    case extensionDisabled
    case extensionStartingUp
    case permissionDenied
    case pathNotFound
    case busyOrAlreadyMounted
    case invalidPasswordOrMasterKey
    case mountPointNotEmpty
    case generic(code: Int, message: String)

    public static func parse(code: Int, message: String) -> MountError {
        let raw = message
        if FSModuleProbe.interpret(mountStderr: raw) == .disabled {
            return .extensionDisabled
        }
        if raw.contains("Couldn't communicate with a helper application") {
            return .extensionStartingUp
        }
        if raw.contains("Permission denied") || code == EACCES {
            return .permissionDenied
        }
        if raw.contains("No such file or directory") || code == ENOENT {
            return .pathNotFound
        }
        if raw.contains("Resource busy") || raw.contains("already mounted") || code == EBUSY {
            return .busyOrAlreadyMounted
        }
        if raw.contains("invalid password") || raw.contains("Authentication failed") {
            return .invalidPasswordOrMasterKey
        }
        if raw.contains("Directory not empty") || raw.contains("not empty") || code == ENOTEMPTY {
            return .mountPointNotEmpty
        }
        return .generic(code: code, message: message)
    }

    public var errorDescription: String? {
        switch self {
        case .extensionDisabled:
            return "FSKit extension is disabled by system; cannot mount. Go to System Settings → General → Login Items & Extensions → File System Extensions and enable GocryptKit, then try again."
        case .extensionStartingUp:
            return "Extension is still starting up (known cold start behavior). Please click Mount again."
        case .permissionDenied:
            return "Permission denied accessing vault or mount directory."
        case .pathNotFound:
            return "Vault directory or mountpoint does not exist."
        case .busyOrAlreadyMounted:
            return "Mount point is already mounted or busy."
        case .invalidPasswordOrMasterKey:
            return "Authentication failed: invalid password or masterkey."
        case .mountPointNotEmpty:
            return "Target mount directory is not empty."
        case .generic(let code, let msg):
            let useful = msg.split(separator: "\n").filter { !$0.contains("/Library/Filesystems/gocryptfs.fs") }.joined(separator: "\n")
            let desc = useful.isEmpty ? msg : useful
            return code != 0 ? "\(desc) (code \(code))" : desc
        }
    }
}

/// Strongly-typed error classifications for filesystem unmount operations.
public enum UnmountError: LocalizedError, Sendable, Equatable {
    case busy(message: String)
    case generic(code: Int, message: String)

    public static func parse(code: Int, message: String) -> UnmountError {
        let raw = message.lowercased()
        if raw.contains("busy") || raw.contains("in use") || code == EBUSY {
            return .busy(message: message)
        }
        return .generic(code: code, message: message)
    }

    public var isBusy: Bool {
        if case .busy = self { return true }
        return false
    }

    public var errorDescription: String? {
        switch self {
        case .busy:
            return "Volume is in use by another application. Please close open files/Finder windows and try again."
        case .generic(let code, let msg):
            return code != 0 ? "Unmount failed (code \(code)): \(msg)" : msg
        }
    }
}
