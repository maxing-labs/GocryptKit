import XCTest
import VaultCore

/// F-14: the default mount root must not be enterable by other accounts.
final class MountPointSecurityTests: XCTestCase {
    private var base: URL!

    override func setUpWithError() throws {
        // Under /private/tmp on purpose: every ancestor there is world-searchable.
        base = URL(fileURLWithPath: "/private/tmp/gk-mountroot-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: base)
    }

    private func mode(_ url: URL) throws -> Int {
        try XCTUnwrap(FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber).intValue
    }

    func testMissingRootIsCreatedPrivate() throws {
        let root = base.appendingPathComponent("Volumes")
        XCTAssertTrue(try MountPointSecurity.makePrivate(root))
        XCTAssertEqual(try mode(root), 0o700)
    }

    func testExistingOpenRootIsTightened() throws {
        let root = base.appendingPathComponent("Volumes")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
        XCTAssertTrue(MountPointSecurity.isReachableByOthers(root))
        XCTAssertTrue(try MountPointSecurity.makePrivate(root))
        XCTAssertEqual(try mode(root), 0o700)
        XCTAssertFalse(MountPointSecurity.isReachableByOthers(root))
        XCTAssertFalse(try MountPointSecurity.makePrivate(root), "an already private directory must not be touched again")
    }

    func testMountPointBelowPrivateRootIsNotReachable() throws {
        let root = base.appendingPathComponent("Volumes")
        try MountPointSecurity.makePrivate(root)
        let mountPoint = root.appendingPathComponent("vault")
        try FileManager.default.createDirectory(at: mountPoint, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
        XCTAssertFalse(MountPointSecurity.isReachableByOthers(mountPoint))
        XCTAssertFalse(MountPointSecurity.isReachableByOthers(base.appendingPathComponent("missing")))
    }

    func testFilesAndForeignDirectoriesAreLeftAlone() throws {
        let file = base.appendingPathComponent("not-a-directory")
        try Data().write(to: file)
        XCTAssertFalse(try MountPointSecurity.makePrivate(file))
        XCTAssertFalse(try MountPointSecurity.makePrivate(URL(fileURLWithPath: "/private/tmp")), "not ours to change")
    }
}
