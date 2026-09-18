import XCTest
@testable import VaultCore

final class VaultRegistryTests: XCTestCase {
    private var tmp: URL!

    override func setUpWithError() throws {
        tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("VaultRegistryTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tmp)
    }

    /// Creates a directory that looks like a gocryptfs vault: containing a `gocryptfs.conf` file suffices,
    /// as the registration step does not parse its contents.
    private func makeFakeVaultDir(named name: String) throws -> URL {
        let dir = tmp.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data("{}".utf8).write(to: dir.appendingPathComponent("gocryptfs.conf"))
        return dir
    }

    // MARK: - Registration

    func testAddRegistersVaultWithDerivedDefaults() throws {
        let dir = try makeFakeVaultDir(named: "photos")
        var registry = VaultRegistry()
        let vault = try registry.add(cipherDir: dir)

        XCTAssertEqual(vault.name, "photos")
        XCTAssertEqual(vault.cipherDirPath, Vault.normalize(path: dir.path))
        XCTAssertTrue(vault.mountPointPath.hasSuffix("/Volumes/photos"))
        XCTAssertEqual(registry.vaults.count, 1)
    }

    func testAddRejectsDirectoryWithoutConfig() throws {
        let dir = tmp.appendingPathComponent("empty")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var registry = VaultRegistry()

        XCTAssertThrowsError(try registry.add(cipherDir: dir)) { error in
            XCTAssertEqual(error as? VaultRegistryError,
                           .notAVault(Vault.normalize(path: dir.path)))
        }
        XCTAssertTrue(registry.vaults.isEmpty)
    }

    func testAddRejectsDuplicateCipherDir() throws {
        let dir = try makeFakeVaultDir(named: "docs")
        var registry = VaultRegistry()
        try registry.add(cipherDir: dir)

        XCTAssertThrowsError(try registry.add(cipherDir: dir)) { error in
            XCTAssertEqual(error as? VaultRegistryError, .duplicate(existingName: "docs"))
        }
        XCTAssertEqual(registry.vaults.count, 1)
    }

    /// The same directory referenced via different path spellings must resolve to the same vault;
    /// otherwise, the list would display duplicate entries pointing to the same data with conflicting statuses.
    func testAddTreatsUnnormalizedPathAsDuplicate() throws {
        let dir = try makeFakeVaultDir(named: "notes")
        var registry = VaultRegistry()
        try registry.add(cipherDir: dir)

        let roundabout = tmp.appendingPathComponent("notes/../notes")
        XCTAssertThrowsError(try registry.add(cipherDir: roundabout))
        XCTAssertEqual(registry.vaults.count, 1)
    }

    // MARK: - Modification and Deletion

    func testUpdateReplacesMatchingVaultInPlace() throws {
        let dir = try makeFakeVaultDir(named: "a")
        var registry = VaultRegistry()
        var vault = try registry.add(cipherDir: dir)

        vault.name = "Renamed Vault"
        vault.mountPointPath = "/tmp/elsewhere"
        registry.update(vault)

        XCTAssertEqual(registry.vaults.count, 1)
        XCTAssertEqual(registry.vaults[0].name, "Renamed Vault")
        XCTAssertEqual(registry.vaults[0].mountPointPath, "/tmp/elsewhere")
    }

    func testUpdateIgnoresUnknownVault() throws {
        var registry = VaultRegistry()
        registry.update(Vault(name: "Ghost", cipherDirPath: "/nope", mountPointPath: "/nope"))
        XCTAssertTrue(registry.vaults.isEmpty)
    }

    /// Removing from the registry must only modify the list. The user's ciphertext files on disk must never be touched.
    func testRemoveLeavesCiphertextOnDisk() throws {
        let dir = try makeFakeVaultDir(named: "keepme")
        var registry = VaultRegistry()
        let vault = try registry.add(cipherDir: dir)

        registry.remove(id: vault.id)

        XCTAssertTrue(registry.vaults.isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: dir.appendingPathComponent("gocryptfs.conf").path))
    }

    // MARK: - Persistence

    func testLoadReturnsEmptyRegistryWhenFileMissing() throws {
        let url = tmp.appendingPathComponent("does-not-exist.json")
        XCTAssertTrue(try VaultRegistry.load(from: url).vaults.isEmpty)
    }

    func testSaveThenLoadRoundTrips() throws {
        let dir = try makeFakeVaultDir(named: "roundtrip")
        var registry = VaultRegistry()
        try registry.add(cipherDir: dir)

        let url = tmp.appendingPathComponent("vaults.json")
        try registry.save(to: url)

        XCTAssertEqual(try VaultRegistry.load(from: url), registry)
    }

    func testSaveOverwritesPreviousContents() throws {
        let url = tmp.appendingPathComponent("vaults.json")
        var registry = VaultRegistry()
        try registry.add(cipherDir: try makeFakeVaultDir(named: "one"))
        try registry.save(to: url)

        registry.remove(id: registry.vaults[0].id)
        try registry.save(to: url)

        XCTAssertTrue(try VaultRegistry.load(from: url).vaults.isEmpty)
    }

    func testSaveEnforcesPosix0600Permissions() throws {
        let url = tmp.appendingPathComponent("permissions.json")
        var registry = VaultRegistry()
        try registry.add(cipherDir: try makeFakeVaultDir(named: "perm"))
        try registry.save(to: url)

        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        let perms = attrs[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600, "vaults.json must be restricted to 0600 permissions")
    }
}

final class MountTableTests: XCTestCase {
    /// The host system always has the root filesystem mounted, so this call should never return empty.
    func testEntriesIncludesRootFilesystem() {
        let entries = MountTable.entries()
        XCTAssertFalse(entries.isEmpty)
        XCTAssertTrue(entries.contains { $0.mountPoint == "/" })
    }

    /// Converting fixed-size C char arrays to Swift String is error-prone (over-reading yields garbage trailing bytes).
    func testEntryFieldsAreCleanStrings() {
        for entry in MountTable.entries() {
            XCTAssertFalse(entry.fileSystemType.isEmpty)
            XCTAssertFalse(entry.mountPoint.isEmpty)
            XCTAssertFalse(entry.fileSystemType.contains("\0"))
            XCTAssertFalse(entry.mountPoint.contains("\0"))
        }
    }

    func testGocryptfsMountsIsKeyedByCanonicalCipherDir() {
        for (key, entry) in MountTable.gocryptfsMounts() {
            XCTAssertEqual(key, Vault.canonicalKey(path: entry.sourcePath))
            XCTAssertEqual(entry.fileSystemType, MountTable.gocryptfsTypeName)
            // Key must be a file path, not containing a file:// scheme.
            XCTAssertTrue(key.hasPrefix("/"), "Key is not an absolute path: \(key)")
        }
    }
}

/// Decoding of `f_mntfromname`. FSKit places a file URL here rather than a bare path;
/// failing to decode properly results in volumes appearing permanently unmounted in the UI.
final class MountSourceDecodingTests: XCTestCase {
    func testDecodesFileURLWithTrailingSlash() {
        // Captured from real mount execution: mount -t gocryptfs /tmp/x /tmp/y
        XCTAssertEqual(MountTable.decodeSource("file:///tmp/mt-cipher.ZkXHDq/"),
                       "/tmp/mt-cipher.ZkXHDq")
    }

    func testDecodesPercentEncodedPath() {
        XCTAssertEqual(MountTable.decodeSource("file:///Users/me/My%20Vault/"),
                       "/Users/me/My Vault")
    }

    func testLeavesNonURLSourceAlone() {
        XCTAssertEqual(MountTable.decodeSource("/dev/disk3s1"), "/dev/disk3s1")
        XCTAssertEqual(MountTable.decodeSource("map auto_home"), "map auto_home")
    }

    /// The foundation for mount matching: the kernel reports the mount source as /private/tmp/...,
    /// while the user registers /tmp/...; both must match when passed through canonicalKey.
    /// Notice Foundation strips `/private` rather than appending it, so this test asserts agreement
    /// between spellings without hardcoding internal representation.
    func testCanonicalKeyAgreesAcrossPrivateTmpSpellings() throws {
        XCTAssertEqual(Vault.canonicalKey(path: "/tmp"),
                       Vault.canonicalKey(path: "/private/tmp"))

        // Use an existing directory since this reflects the actual matching scenario (mounted vaults must exist).
        let name = "canon-\(UUID().uuidString)"
        let dir = URL(fileURLWithPath: "/tmp").appendingPathComponent(name)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        XCTAssertEqual(Vault.canonicalKey(path: "/tmp/\(name)"),
                       Vault.canonicalKey(path: "/private/tmp/\(name)"))
        XCTAssertEqual(Vault.canonicalKey(path: "/tmp/\(name)/../\(name)"),
                       Vault.canonicalKey(path: "/private/tmp/\(name)"))
    }

    /// Resolves real symbolic links, not just the /private special case.
    func testCanonicalKeyResolvesRealSymlink() throws {
        let base = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("canon-\(UUID().uuidString)")
        let real = base.appendingPathComponent("real")
        let link = base.appendingPathComponent("link")
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: base) }
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)

        XCTAssertEqual(Vault.canonicalKey(path: link.path),
                       Vault.canonicalKey(path: real.path))
    }

    /// `canonicalKey` is strictly for comparison; persistence retains the un-canonicalized path,
    /// preventing external drive paths from mutating when disconnected.
    func testNormalizeDoesNotResolveSymlinks() {
        XCTAssertEqual(Vault.normalize(path: "/tmp/somewhere"), "/tmp/somewhere")
    }
}
