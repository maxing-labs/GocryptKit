import XCTest
@testable import VaultCore

/// I-8: the paths that tie a vault to its mount must resolve the same way everywhere.
final class MountIdentityTests: XCTestCase {
    private var tmp: URL!

    override func setUpWithError() throws {
        tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("MountIdentityTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tmp)
    }

    private func makeFakeVaultDir(_ relative: String) throws -> URL {
        let dir = tmp.appendingPathComponent(relative)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data("{}".utf8).write(to: dir.appendingPathComponent("gocryptfs.conf"))
        return dir
    }

    /// FSKit records "unknown" as the source of a vault whose file URL does not
    /// fit f_mntfromname (a long, non-ASCII path). The host's own mount record
    /// names the vault instead; otherwise the UI shows it as not mounted.
    func testUnknownSourceIsResolvedThroughTheMountRecord() {
        let long = tmp.appendingPathComponent("long-mnt"), other = tmp.appendingPathComponent("other-mnt")
        MountRecordStore.rememberCipherDir(URL(fileURLWithPath: "/vaults/long"), for: long, mountOnName: long.path)
        MountRecordStore.rememberCipherDir(URL(fileURLWithPath: "/vaults/other"), for: other, mountOnName: other.path)
        defer {
            _ = MountRecordStore.forgetCipherDir(for: long, mountOnName: long.path)
            _ = MountRecordStore.forgetCipherDir(for: other, mountOnName: other.path)
        }
        let entries = [long, other].map {
            MountTable.Entry(fileSystemType: MountTable.gocryptfsTypeName, source: "unknown", mountPoint: $0.path)
        }
        let mounts = MountTable.gocryptfsMounts(in: entries, ownedBy: nil)
        XCTAssertEqual(mounts["/vaults/long"]?.mountPoint, long.path)
        XCTAssertEqual(mounts["/vaults/other"]?.mountPoint, other.path)
    }

    /// The 2-second mount table poll runs on the main thread. It must take the
    /// mount table's mount point as is: resolving it is answered by the mounted
    /// volume's extension and hangs the UI while FSKit is stuck. Here resolving
    /// would land elsewhere (a symlink stands in for "enters the volume").
    func testLiveMountIsLookedUpWithoutResolvingItsMountPoint() throws {
        let mountPoint = tmp.appendingPathComponent("mnt"), elsewhere = tmp.appendingPathComponent("elsewhere")
        try FileManager.default.createDirectory(at: elsewhere, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: mountPoint, withDestinationURL: elsewhere)
        MountRecordStore.rememberCipherDir(URL(fileURLWithPath: "/vaults/x"), for: mountPoint, mountOnName: mountPoint.path)
        defer { _ = MountRecordStore.forgetCipherDir(for: mountPoint, mountOnName: mountPoint.path) }

        let entry = MountTable.Entry(fileSystemType: MountTable.gocryptfsTypeName, source: "unknown", mountPoint: mountPoint.path)
        XCTAssertEqual(MountTable.gocryptfsMounts(in: [entry], ownedBy: nil)["/vaults/x"]?.mountPoint, mountPoint.path)
    }

    /// The mount record is keyed like everything else (realpath): another
    /// spelling of the same mount point finds it.
    func testMountRecordIgnoresTheSpellingOfTheMountPoint() throws {
        let mountPoint = tmp.appendingPathComponent("MountPoint")
        try FileManager.default.createDirectory(at: mountPoint, withIntermediateDirectories: true)
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "MountIdentityTests-\(UUID().uuidString)"))
        MountRecordStore.rememberCipherDir(URL(fileURLWithPath: "/vaults/x"), for: mountPoint, userDefaults: defaults)
        let respelled = URL(fileURLWithPath: tmp.appendingPathComponent("mountpoint").path)
        XCTAssertEqual(MountRecordStore.forgetCipherDir(for: respelled, userDefaults: defaults), "/vaults/x")
    }

    /// Two vaults whose directories share a name must not share the default mount point.
    func testVaultsWithTheSameNameGetDistinctMountPoints() throws {
        var registry = VaultRegistry()
        let first = try registry.add(cipherDir: try makeFakeVaultDir("one/secret"))
        let second = try registry.add(cipherDir: try makeFakeVaultDir("two/secret"))
        let third = registry.addCreated(cipherDir: try makeFakeVaultDir("three/Secret"))
        let mountPoints = [first, second, third].map { $0.mountPointPath.lowercased() }
        XCTAssertEqual(Set(mountPoints).count, 3, "\(mountPoints)")
        XCTAssertEqual([first, second, third].map(\.name), ["secret", "secret", "Secret"])
    }

    /// F-18: the data volume's firmlinks give every path under /Users, /private …
    /// a second spelling under /System/Volumes/Data that realpath keeps. Through it
    /// the same vault was mounted twice.
    func testFirmlinkSpellingHasTheSameCanonicalKey() {
        let path = Vault.canonicalKey(path: tmp.path)
        XCTAssertFalse(path.hasPrefix("/System/Volumes/Data/"))
        XCTAssertEqual(Vault.canonicalKey(path: "/System/Volumes/Data" + path), path)
        // A path that exists only on the data volume keeps its spelling.
        XCTAssertEqual(Vault.canonicalKey(path: "/System/Volumes/Data"), "/System/Volumes/Data")
    }

    /// R-2: the extension reads gocryptfs.conf following symlinks. A conf linked
    /// into a mounted vault deadlocks FSKit like a nested vault, although the
    /// vault's directory itself is outside. statfs follows symlinks; the fake
    /// does the same through realpath.
    func testVaultWhoseConfLiesInAMountedVaultIsFound() throws {
        let outer = try makeFakeVaultDir("outer-mounted")
        let inner = tmp.appendingPathComponent("inner")
        try FileManager.default.createDirectory(at: inner, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: inner.appendingPathComponent("gocryptfs.conf"),
                                                   withDestinationURL: outer.appendingPathComponent("gocryptfs.conf"))
        let outerKey = Vault.canonicalKey(path: outer.path)
        let volumeOf: (String) -> String? = { path in
            Vault.canonicalKey(path: path).hasPrefix(outerKey + "/") ? "/Volumes/outer" : nil
        }
        XCTAssertNil(volumeOf(inner.path), "the directory alone looks fine")
        XCTAssertEqual(MountTable.gocryptfsVolume(holdingVaultAt: inner.path, volumeOf: volumeOf), "/Volumes/outer")
        XCTAssertNil(MountTable.gocryptfsVolume(holdingVaultAt: try makeFakeVaultDir("plain").path, volumeOf: volumeOf))
    }

    /// A vault inside a mounted vault is refused before mounting (FSKit deadlocks
    /// on it). Ordinary directories are not inside a gocryptfs volume.
    func testOrdinaryDirectoryIsNotInsideAVault() throws {
        XCTAssertNil(MountTable.gocryptfsVolume(containing: tmp.path))
        XCTAssertNil(MountTable.gocryptfsVolume(holdingVaultAt: try makeFakeVaultDir("ordinary").path))
        XCTAssertNil(MountTable.gocryptfsVolume(containing: "/nonexistent-\(UUID().uuidString)"))
        XCTAssertNotNil(MountError.insideMountedVault(at: "/Volumes/outer").errorDescription)
    }
}
