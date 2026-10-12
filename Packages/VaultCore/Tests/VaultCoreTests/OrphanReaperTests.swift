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

    func testIncludeMountContextReapsBothCredentialAndMountContext() {
        let path = "/Users/test/vault1"
        let key = Vault.canonicalKey(path: path)
        let ctxKey = MountContextStore.accountKey(for: path)

        let reaped = OrphanReaper.accountsToReap(
            knownVaultPaths: [path],
            mountedCanonicalKeys: [],
            includeMountContext: true
        )
        XCTAssertEqual(reaped, [key, ctxKey])
    }

    // MARK: - Age-based reaping over stored items (F-16, F-17)

    private func item(_ account: String, age: TimeInterval?, now: Date) -> KeychainStore.StoredItem {
        KeychainStore.StoredItem(account: account, savedAt: age.map { now.addingTimeInterval(-$0) })
    }

    func testFreshCredentialOfAnotherProcessIsNotReaped() {
        // The CLI stored this a moment ago and is still mounting; the GUI must keep its hands off.
        let now = Date()
        let stored = [item("/vaults/cli", age: 3, now: now), item("mountctx:/vaults/cli", age: 3, now: now)]
        XCTAssertEqual(OrphanReaper.accountsToReap(stored: stored, protectedVaultKeys: [], now: now), [])
    }

    func testStaleCredentialOfUnregisteredVaultIsReaped() {
        // Left behind by an interrupted CLI mount of a vault the app has never heard of.
        let now = Date()
        let stored = [item("/vaults/unregistered", age: 600, now: now),
                      item("mountctx:/vaults/unregistered", age: 600, now: now),
                      item("/vaults/undated", age: nil, now: now)]
        XCTAssertEqual(OrphanReaper.accountsToReap(stored: stored, protectedVaultKeys: [], now: now),
                       ["/vaults/unregistered", "mountctx:/vaults/unregistered", "/vaults/undated"])
    }

    func testMountedAndInFlightVaultsAreProtectedRegardlessOfAge() {
        let now = Date()
        let stored = [item("/vaults/mounted", age: 600, now: now),
                      item("mountctx:/vaults/mounted", age: 600, now: now),
                      item("/vaults/orphan", age: 600, now: now)]
        XCTAssertEqual(OrphanReaper.accountsToReap(stored: stored, protectedVaultKeys: ["/vaults/mounted"], now: now),
                       ["/vaults/orphan"])
    }

    func testGracePeriodBoundary() {
        let now = Date()
        let stored = [item("/vaults/young", age: OrphanReaper.gracePeriod - 1, now: now),
                      item("/vaults/old", age: OrphanReaper.gracePeriod + 1, now: now)]
        XCTAssertEqual(OrphanReaper.accountsToReap(stored: stored, protectedVaultKeys: [], now: now), ["/vaults/old"])
    }
}
