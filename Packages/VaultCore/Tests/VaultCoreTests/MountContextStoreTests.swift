import XCTest
@testable import VaultCore

final class MountContextStoreTests: XCTestCase {

    let testCipherPath = "/tmp/test-gocryptfskit-cipher"

    override func setUp() {
        super.setUp()
        setenv("GOCRYPTFSKIT_KEYCHAIN_ACCESS_GROUP", "", 1)
        MountContextStore.delete(for: testCipherPath)
    }

    override func tearDown() {
        MountContextStore.delete(for: testCipherPath)
        unsetenv("GOCRYPTFSKIT_KEYCHAIN_ACCESS_GROUP")
        super.tearDown()
    }

    func testSaveAndLoadMountContext() {
        let expectedName = "my-test-vault_READ_ONLY"
        let context = MountContext(
            volumeName: expectedName,
            isReadOnly: true,
            mountPoint: "/Users/test/Volumes/my-test-vault_READ_ONLY"
        )

        let saved = MountContextStore.save(context, for: testCipherPath)
        XCTAssertTrue(saved)

        let loaded = MountContextStore.load(for: testCipherPath)
        XCTAssertNotNil(loaded)
        XCTAssertEqual(loaded?.volumeName, expectedName)
        XCTAssertEqual(loaded?.isReadOnly, true)
        XCTAssertEqual(loaded?.mountPoint, "/Users/test/Volumes/my-test-vault_READ_ONLY")
    }

    func testCanonicalPathEquivalence() {
        let rawPath = "/tmp/test-canonical-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: rawPath, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: rawPath) }

        let context = MountContext(
            volumeName: "canonical_vault_READ_ONLY",
            isReadOnly: true,
            mountPoint: "/tmp/mount"
        )
        MountContextStore.save(context, for: rawPath)

        // /tmp is symlinked to /private/tmp on macOS; realpath resolves existing paths
        let resolvedPath = (rawPath as NSString).resolvingSymlinksInPath
        let canonicalLoaded = MountContextStore.load(for: resolvedPath)
        XCTAssertNotNil(canonicalLoaded)
        XCTAssertEqual(canonicalLoaded?.volumeName, "canonical_vault_READ_ONLY")

        MountContextStore.delete(for: rawPath)
    }

    func testExpiredContextReturnsNil() {
        let staleDate = Date().addingTimeInterval(-(MountContext.defaultTTL + 10))
        let expiredContext = MountContext(
            volumeName: "stale_vault",
            isReadOnly: false,
            mountPoint: "/tmp/mount",
            createdAt: staleDate
        )
        XCTAssertTrue(expiredContext.isExpired)

        MountContextStore.save(expiredContext, for: testCipherPath)
        let loaded = MountContextStore.load(for: testCipherPath)
        XCTAssertNil(loaded, "Expired mount context must return nil and be cleaned up")
    }

    func testDeleteMountContext() {
        let context = MountContext(
            volumeName: "to-be-deleted",
            isReadOnly: false,
            mountPoint: "/tmp/mount"
        )
        MountContextStore.save(context, for: testCipherPath)
        XCTAssertNotNil(MountContextStore.load(for: testCipherPath))

        MountContextStore.delete(for: testCipherPath)
        XCTAssertNil(MountContextStore.load(for: testCipherPath))
    }
}
