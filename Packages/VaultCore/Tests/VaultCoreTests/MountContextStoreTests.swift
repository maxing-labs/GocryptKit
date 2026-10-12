import XCTest
@testable import VaultCore

final class MountContextStoreTests: XCTestCase {

    let testCipherPath = "/tmp/test-gocryptfskit-cipher"

    /// Whether the keychain calls go to this test's own service.
    private var isolated: Bool { KeychainStore.serviceName != KeychainConfig.defaultServiceName }

    override func setUpWithError() throws {
        try super.setUpWithError()
        setenv("GOCRYPTFSKIT_KEYCHAIN_ACCESS_GROUP", "", 1)
        // A service of this test's own: the login keychain also holds the app's items.
        setenv("GOCRYPTFSKIT_KEYCHAIN_SERVICE_NAME", "com.xwei.GocryptfsKit.tests.\(UUID().uuidString)", 1)
        // Release builds ignore the override (KeychainConfig).
        guard isolated else { throw XCTSkip("the keychain service override needs a DEBUG build") }
    }

    override func tearDown() {
        if isolated {
            for item in KeychainStore.storedItems() {
                KeychainStore.deleteCredential(account: item.account)
            }
        }
        unsetenv("GOCRYPTFSKIT_KEYCHAIN_SERVICE_NAME")
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

    func testStoredItemsListsAccountsWithTheirAge() {
        let context = MountContext(volumeName: "listed", isReadOnly: false, mountPoint: "/tmp/listed")
        XCTAssertTrue(MountContextStore.save(context, for: testCipherPath))
        let account = MountContextStore.accountKey(for: testCipherPath)
        let listed = KeychainStore.storedItems().first { $0.account == account }
        XCTAssertNotNil(listed, "a saved item must be enumerable without knowing its vault")
        if let savedAt = listed?.savedAt {
            XCTAssertLessThan(abs(savedAt.timeIntervalSinceNow), 60)
        } else {
            XCTFail("stored item has no date")
        }
        XCTAssertEqual(MountContextStore.vaultKey(forAccount: account), Vault.canonicalKey(path: testCipherPath))
        XCTAssertEqual(MountContextStore.vaultKey(forAccount: "/plain/account"), "/plain/account")
        MountContextStore.delete(for: testCipherPath)
        XCTAssertFalse(KeychainStore.storedItems().contains { $0.account == account })
    }

    /// A-8: the tests write to a keychain service of their own, never to the app's.
    func testItemsStayOutOfTheAppsService() {
        let context = MountContext(volumeName: "isolated", isReadOnly: false, mountPoint: "/tmp/isolated")
        XCTAssertTrue(MountContextStore.save(context, for: testCipherPath))
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainConfig.defaultServiceName,
            kSecAttrAccount as String: MountContextStore.accountKey(for: testCipherPath),
        ]
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, nil), errSecItemNotFound)
    }
}
