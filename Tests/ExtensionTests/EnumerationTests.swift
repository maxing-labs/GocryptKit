import Foundation
import FSKit
import ObjectiveC
import VaultCore
import XCTest

/// Takes a few entries per call, as the kernel does with a small buffer.
/// FSDirectoryEntryPacker has no public initializer, so the instance is made
/// without one and keeps its state in statics.
final class BatchPacker: FSDirectoryEntryPacker {
    nonisolated(unsafe) static var room = 0
    nonisolated(unsafe) static var names: [String] = []
    nonisolated(unsafe) static var lastCookie = FSDirectoryCookie(0)

    static func make(room: Int) -> BatchPacker {
        Self.room = room
        Self.names = []
        return class_createInstance(BatchPacker.self, 0) as! BatchPacker
    }

    override func packEntry(name: FSFileName, itemType: FSItem.ItemType, itemID: FSItem.Identifier,
                            nextCookie: FSDirectoryCookie, attributes: FSItem.Attributes?) -> Bool {
        guard Self.room > 0 else { return false }
        Self.room -= 1
        Self.names.append(name.string ?? "")
        Self.lastCookie = nextCookie
        return true
    }
}

/// I-5: a directory that changes between two enumeration calls must not make
/// the listing skip or repeat entries that were there all along.
final class EnumerationTests: VolumeTestCase {

    private func enumerate(from cookie: FSDirectoryCookie, room: Int) throws -> (names: [String], next: FSDirectoryCookie) {
        let packer = BatchPacker.make(room: room)
        var error: Error?
        BatchPacker.lastCookie = cookie
        volume.enumerateDirectory(volume.rootItem, startingAt: cookie, verifier: FSDirectoryVerifier(0),
                                  attributes: nil, packer: packer) { _, e in error = e }
        if let error { throw error }
        return (BatchPacker.names, BatchPacker.lastCookie)
    }

    /// Creates `count` files. The vault also holds `.fseventsd`, which the checks ignore.
    private func names(_ count: Int) throws -> Set<String> {
        let names = (0..<count).map { String(format: "f%02d", $0) }
        for name in names { _ = try create(name) }
        return Set(names)
    }

    func testRemovalBetweenBatchesSkipsNothing() throws {
        var expected = try names(12)
        let first = try enumerate(from: FSDirectoryCookie(0), room: 4)
        let gone = try lookup(try XCTUnwrap(first.names.first(where: expected.contains)))
        try remove(gone)
        expected.remove(gone.name)
        let rest = try enumerate(from: first.next, room: 100)
        let listed = first.names + rest.names
        XCTAssertEqual(expected.subtracting(listed), [], "entries skipped after a removal")
        XCTAssertEqual(listed.count, Set(listed).count, "entries listed twice")
    }

    func testCreationBetweenBatchesRepeatsNothing() throws {
        let expected = try names(12)
        let first = try enumerate(from: FSDirectoryCookie(0), room: 4)
        for name in ["a", "b", "c"] { _ = try create(name) }  // may or may not show up
        let rest = try enumerate(from: first.next, room: 100)
        let listed = first.names + rest.names
        XCTAssertEqual(expected.subtracting(listed), [], "entries skipped after a creation")
        XCTAssertEqual(listed.count, Set(listed).count, "entries listed twice after a creation")
    }

    private func listOnePerCall() throws -> [String] {
        var listed: [String] = []
        var cookie = FSDirectoryCookie(0)
        for _ in 0..<100 {
            let batch = try enumerate(from: cookie, room: 1)
            if batch.names.isEmpty { break }
            listed += batch.names
            cookie = batch.next
        }
        return listed
    }

    /// R-3: two names chosen so that their FNV-1a keys collide. With the cookie
    /// "key + 1" the second one was never listed when a batch ended between them,
    /// so anyone who can name files could hide one from backup tools.
    func testCraftedKeyCollisionHidesNothing() throws {
        let expected: Set<String> = ["1c5e5729dbef2a8f", "0372cceaf3761fba", "a", "b"]
        for name in expected { _ = try create(name) }
        let listed = try listOnePerCall()
        XCTAssertEqual(expected.subtracting(listed), [], "entries hidden by a key collision")
        XCTAssertEqual(listed.count, Set(listed).count, "entries listed twice")
    }

    /// R-3: names that do share a key are still listed one by one.
    func testNamesSharingAKeyAreAllListed() throws {
        volume.listingKey = { _ in 7 }
        let expected = try names(6)
        let listed = try listOnePerCall()
        XCTAssertEqual(listed.filter(expected.contains).sorted(), expected.sorted())
        XCTAssertEqual(listed.count, Set(listed).count, "entries listed twice")
    }

    func testUnchangedDirectoryListsEverythingOnce() throws {
        let expected = try names(12)
        var listed: [String] = []
        var cookie = FSDirectoryCookie(0)
        for _ in 0..<10 {
            let batch = try enumerate(from: cookie, room: 5)
            if batch.names.isEmpty { break }
            listed += batch.names
            cookie = batch.next
        }
        XCTAssertEqual(listed.filter(expected.contains).sorted(), expected.sorted())
    }
}
