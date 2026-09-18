import Foundation
import FSKit
import OSLog
import VaultCore

private let logger = Logger(subsystem: "com.xwei.GocryptKit.AppEx", category: "GocryptfsFileSystem")

@objc
final class GocryptfsFileSystem: FSUnaryFileSystem, FSUnaryFileSystemOperations, @unchecked Sendable {

    var resource: FSPathURLResource?
    var volume: GocryptfsVolume?

    public override init() {
        super.init()
        logger.debug("GocryptfsFileSystem initialized")
    }

    public func probeResource(resource: FSResource, replyHandler: @escaping (FSProbeResult?, Error?) -> Void) {
        guard let urlResource = resource as? FSPathURLResource else {
            logger.error("probeResource: Resource is not an FSPathURLResource")
            return replyHandler(nil, POSIXError(.ENODEV))
        }

        let cipherURL = urlResource.url
        let confURL = cipherURL.appendingPathComponent("gocryptfs.conf")

        var isDir: ObjCBool = false
        if !FileManager.default.fileExists(atPath: confURL.path, isDirectory: &isDir) || isDir.boolValue {
            logger.debug("probeResource: gocryptfs.conf not found at \(cipherURL.path, privacy: .private)")
            return replyHandler(nil, POSIXError(.ENODEV))
        }

        let dirName = cipherURL.lastPathComponent
        let containerUUID = UUID()
        let containerID = FSContainerIdentifier(uuid: containerUUID)
        let probeResult = FSProbeResult.usable(name: dirName + "_gocryptfs", containerID: containerID)
        logger.info("probeResource: recognized gocryptfs volume at \(cipherURL.path, privacy: .private)")
        replyHandler(probeResult, nil)
    }

    public func loadResource(resource: FSResource, options: FSTaskOptions, replyHandler: @escaping (FSVolume?, Error?) -> Void) {
        guard let urlResource = resource as? FSPathURLResource else {
            logger.error("loadResource: Invalid resource type")
            return replyHandler(nil, POSIXError(.EINVAL))
        }

        guard urlResource.url.startAccessingSecurityScopedResource() else {
            logger.error("loadResource: Failed to access security scoped resource for \(urlResource.url.path, privacy: .private)")
            return replyHandler(nil, POSIXError(.EACCES))
        }

        self.resource = urlResource

        // Parse options for vault=<uuid>
        var vaultUUID: String? = nil
        for opt in options.taskOptions {
            if opt.contains("vault=") {
                let parts = opt.components(separatedBy: "vault=")
                if parts.count > 1 {
                    vaultUUID = parts[1].components(separatedBy: ",").first
                }
            }
        }

        // Credentials come from the shared Keychain access group, written by the
        // host app after it has validated the password the user typed. There is
        // deliberately no fallback: an unlock attempt with no stored credential
        // must fail rather than silently try a guess.
        var engine: GocryptfsEngine? = nil

        func tryCredential(account: String) -> GocryptfsEngine? {
            guard let data = KeychainReader.loadCredential(account: account) else {
                logger.error("tryCredential: loadCredential returned nil for account \(account, privacy: .public)")
                return nil
            }
            guard let payload = VaultCredentialPayload.deserialize(from: data) else {
                logger.error("tryCredential: deserialize returned nil for data count \(data.count, privacy: .public)")
                return nil
            }
            let credential: VaultCredential = switch payload {
            case .password(let pwd): .password(pwd)
            case .scryptHash(let hash): .scryptHash(hash)
            }
            do {
                return try GocryptfsEngine(cipherDir: urlResource.url, credential: credential)
            } catch {
                logger.error("tryCredential: GocryptfsEngine initialization failed: \(error.localizedDescription, privacy: .public)")
                return nil
            }
        }

        if let uuid = vaultUUID {
            engine = tryCredential(account: uuid)
        }
        if engine == nil {
            engine = tryCredential(account: Vault.canonicalKey(path: urlResource.url.path))
        }

        guard let activeEngine = engine else {
            logger.error("loadResource: Authentication failed or no valid credential found")
            // Clean up any credential even on auth failure to prevent
            // brute-force dictionary remnants lingering in the Keychain.
            if let uuid = vaultUUID {
                KeychainReader.deleteCredential(account: uuid)
            }
            KeychainReader.deleteCredential(account: Vault.canonicalKey(path: urlResource.url.path))
            urlResource.url.stopAccessingSecurityScopedResource()
            self.resource = nil
            return replyHandler(nil, POSIXError(.EACCES))
        }

        // Consume-and-destroy: master key is now in memory, remove
        // the credential from the Keychain immediately. Even if the
        // volume is ejected from Finder or umount, no secret remains.
        if let uuid = vaultUUID {
            KeychainReader.deleteCredential(account: uuid)
        }
        KeychainReader.deleteCredential(account: Vault.canonicalKey(path: urlResource.url.path))

        do {
            let vol = try GocryptfsVolume(engine: activeEngine, cipherURL: urlResource.url)
            self.volume = vol
            self.containerStatus = .ready
            logger.info("loadResource: successfully mounted gocryptfs volume")
            replyHandler(vol, nil)
        } catch {
            logger.error("loadResource: failed to create GocryptfsVolume: \(error.localizedDescription, privacy: .private)")
            activeEngine.shutdown()
            urlResource.url.stopAccessingSecurityScopedResource()
            self.resource = nil
            replyHandler(nil, error)
        }
    }

    public func unloadResource(resource: FSResource, options: FSTaskOptions, replyHandler: @escaping (Error?) -> Void) {
        guard let urlResource = resource as? FSPathURLResource, let loaded = self.resource, loaded.url == urlResource.url else {
            logger.error("unloadResource: Resource mismatch or not loaded")
            return replyHandler(POSIXError(.EINVAL))
        }

        if let vol = self.volume {
            vol.unmount { }
            self.volume = nil
        }

        loaded.url.stopAccessingSecurityScopedResource()
        self.resource = nil
        logger.info("unloadResource: successfully unmounted")
        replyHandler(nil)
    }
}
