import XCTest
@testable import VaultCore

final class OrphanReaperTests: XCTestCase {

    func testNoVaultsReturnsEmpty() {
        let reaped = OrphanReaper.accountsToReap(
            knownVaultPaths: [],
            mountedCanonicalKeys: ["/private/var/folders/vault1"]
        )
        XCTAssertTrue(reaped.isEmpty)
    }

    func testAllVaultsMountedReturnsEmpty() {
        let path1 = "/Users/test/vault1"
        let path2 = "/Users/test/vault2"
        let key1 = Vault.canonicalKey(path: path1)
        let key2 = Vault.canonicalKey(path: path2)

        let reaped = OrphanReaper.accountsToReap(
            knownVaultPaths: [path1, path2],
            mountedCanonicalKeys: [key1, key2]
        )
        XCTAssertTrue(reaped.isEmpty)
    }

    func testNoVaultsMountedReturnsAll() {
        let path1 = "/Users/test/vault1"
        let path2 = "/Users/test/vault2"
        let key1 = Vault.canonicalKey(path: path1)
        let key2 = Vault.canonicalKey(path: path2)

        let reaped = OrphanReaper.accountsToReap(
            knownVaultPaths: [path1, path2],
            mountedCanonicalKeys: []
        )
        XCTAssertEqual(reaped, [key1, key2])
    }

    func testPartialMountsReapsOnlyUnmounted() {
        let path1 = "/Users/test/vault1"
        let path2 = "/Users/test/vault2"
        let path3 = "/Users/test/vault3"
        let key1 = Vault.canonicalKey(path: path1)
        let key2 = Vault.canonicalKey(path: path2)
        let key3 = Vault.canonicalKey(path: path3)

        let reaped = OrphanReaper.accountsToReap(
            knownVaultPaths: [path1, path2, path3],
            mountedCanonicalKeys: [key2]
        )
        XCTAssertEqual(reaped, [key1, key3])
    }

    func testCanonicalKeyEquivalencePreventsPrematureReap() {
        // /var is symlinked to /private/var on macOS, and /var/tmp exists
        let rawPath = "/var/tmp"
        let canonicalMountedKey = Vault.canonicalKey(path: "/private/var/tmp")

        let reaped = OrphanReaper.accountsToReap(
            knownVaultPaths: [rawPath],
            mountedCanonicalKeys: [canonicalMountedKey]
        )
        // Since Vault.canonicalKey(path: "/var/tmp") == canonicalMountedKey,
        // it must NOT be reaped!
        XCTAssertTrue(reaped.isEmpty)
    }

    func testDeduplicatesMultipleEntriesForSameVault() {
        let path1 = "/Users/test/vault1"
        let path1WithSlash = "/Users/test/vault1/"
        let key1 = Vault.canonicalKey(path: path1)

        let reaped = OrphanReaper.accountsToReap(
            knownVaultPaths: [path1, path1WithSlash],
            mountedCanonicalKeys: []
        )
        XCTAssertEqual(reaped, [key1])
    }
}
