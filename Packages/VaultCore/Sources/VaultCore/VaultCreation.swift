import Foundation
import libgocryptfs

extension GocryptfsEngine {
    /// Return status codes for `gcfc_init_vault`. Must remain synchronized with
    /// the `initVault*` constants in Engine/libgocryptfs/capi_c.go.
    private enum InitStatus: Int32 {
        case ok = 0
        case badArgs = -1
        case badDir = -2
        case alreadyExists = -3
        case dirNotEmpty = -4
        case badLogN = -5
        case confFailed = -6
        case dirIVFailed = -7
        case internalError = -8
    }

    /// Default value for scrypt logN, consistent with upstream gocryptfs (N = 2^16).
    /// Passing 0 to the engine indicates using this default.
    public static let defaultScryptLogN: Int32 = 0

    /// Initializes a new gocryptfs vault in an existing **empty** directory: generates a random master key,
    /// scrypt-derived key wrapping, `gocryptfs.conf`, and `gocryptfs.diriv` at the root directory.
    ///
    /// Returns the 32-byte scrypt hash. It is functionally equivalent to the plaintext password
    /// and can be passed directly as `VaultCredential.scryptHash` when mounting, avoiding a redundant
    /// multi-second key derivation step. Consequently, it must receive the exact same security treatment
    /// as passwords: never persist to disk, never log, and wipe from memory immediately after use.
    ///
    /// - Parameter scryptLogN: The CPU/memory cost parameter for scrypt (N = 2^logN).
    ///   A value of 0 indicates the default of 16. Lower values should only be used in tests,
    ///   as reducing this parameter significantly weakens password security against brute-force attacks.
    @discardableResult
    public static func createVault(
        at cipherDir: URL,
        password: String,
        scryptLogN: Int32 = defaultScryptLogN
    ) throws -> Data {
        // Empty passwords are also rejected by the engine; checking early provides a precise
        // VaultError rather than a generic "bad args". Under no circumstances will a password be fabricated.
        guard !password.isEmpty else { throw VaultError.emptyPassword }

        var hashBuffer = [UInt8](repeating: 0, count: 32)
        defer { for i in hashBuffer.indices { hashBuffer[i] = 0 } }

        let dirCStr = strdup(cipherDir.path)
        defer { free(dirCStr) }
        let pwdCStr = strdup(password)
        defer {
            // The strdup copy of the password is outside Swift ARC management; explicitly zero it out.
            if let pwdCStr { memset_s(pwdCStr, strlen(pwdCStr), 0, strlen(pwdCStr)) }
            free(pwdCStr)
        }

        let raw = gcfc_init_vault(dirCStr, pwdCStr, scryptLogN, &hashBuffer, hashBuffer.count)

        switch InitStatus(rawValue: raw) {
        case .ok:
            let scryptHash = Data(hashBuffer)
            suppressFSEventsLog(in: cipherDir, scryptHash: scryptHash)
            return scryptHash
        case .badArgs:
            throw VaultError.emptyPassword
        case .badDir:
            throw VaultError.invalidCipherDir
        case .alreadyExists:
            throw VaultError.vaultAlreadyExists
        case .dirNotEmpty:
            throw VaultError.directoryNotEmpty
        case .badLogN:
            throw VaultError.invalidScryptLogN
        case .confFailed, .dirIVFailed, .internalError, .none:
            throw VaultError.initFailed(raw)
        }
    }
}

private extension GocryptfsEngine {
    /// Whenever a volume is mounted, macOS `fseventsd` creates a `.fseventsd/` directory at the volume root
    /// and logs file system change events — pure noise (and metadata leakage) for an encrypted volume intended
    /// to sync across devices. Placing an empty file named `no_log` inside `.fseventsd/` instructs `fseventsd`
    /// to cease logging file events on this volume.
    ///
    /// Failure here does not impact vault integrity or usability, so we log a warning rather than failing vault creation.
    static func suppressFSEventsLog(in cipherDir: URL, scryptHash: Data) {
        do {
            let engine = try GocryptfsEngine(cipherDir: cipherDir, credential: .scryptHash(scryptHash))
            defer { engine.shutdown() }
            try engine.mkdir(".fseventsd", mode: 0o700)
            let handle = try engine.openWrite(".fseventsd/no_log", mode: 0o600)
            engine.close(handle)
        } catch {
            // Do not log the path: user directory paths must not be exposed in Console logs.
            NSLog("GocryptKit: could not create .fseventsd/no_log marker in the new vault")
        }
    }
}
