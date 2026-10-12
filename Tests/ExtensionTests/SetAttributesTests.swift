import Foundation
import FSKit
import VaultCore
import XCTest

/// I-1: setAttributes applies times, ownership and flags instead of dropping them.
final class SetAttributesTests: VolumeTestCase {

    private func time(_ sec: Int, _ nsec: Int = 0) -> timespec {
        timespec(tv_sec: sec, tv_nsec: nsec)
    }

    private func assertTime(_ actual: timespec, _ sec: Int, _ nsec: Int = 0, _ what: String,
                            file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual([actual.tv_sec, actual.tv_nsec], [sec, nsec], what, file: file, line: line)
    }

    private func cipherStat(_ plain: String) throws -> stat {
        var st = stat()
        XCTAssertEqual(lstat(try XCTUnwrap(engine.cipherPath(plain)), &st), 0)
        return st
    }

    func testTimesAreApplied() throws {
        for item in [try create("f"), try create("d", type: .directory)] {
            let request = FSItem.SetAttributesRequest()
            request.birthTime = time(1_500_000_000)
            request.modifyTime = time(1_577_934_245, 250_000_000)
            request.accessTime = time(1_614_834_367, 500_000_000)
            try setAttributes(request, on: item)
            for attribute: FSItem.Attribute in [.birthTime, .modifyTime, .accessTime] {
                XCTAssertTrue(request.wasAttributeConsumed(attribute), "\(item.name): \(attribute) not consumed")
            }
            let attrs = try attributes(of: item)
            assertTime(attrs.birthTime, 1_500_000_000, 0, "\(item.name) birth time")
            assertTime(attrs.modifyTime, 1_577_934_245, 250_000_000, "\(item.name) modify time")
            assertTime(attrs.accessTime, 1_614_834_367, 500_000_000, "\(item.name) access time")
        }
    }

    func testFlagsApplyOnlyUserVisibleBits() throws {
        let item = try create("f")
        let cipherPath = try XCTUnwrap(engine.cipherPath("f"))
        XCTAssertEqual(chflags(cipherPath, UInt32(UF_TRACKED)), 0)  // a flag of the ciphertext file itself
        defer { chflags(cipherPath, 0) }
        XCTAssertEqual(try attributes(of: item).flags, 0, "a flag of the ciphertext file leaked into the plaintext view")

        let hide = FSItem.SetAttributesRequest()
        hide.flags = UInt32(UF_HIDDEN)
        try setAttributes(hide, on: item)
        XCTAssertTrue(hide.wasAttributeConsumed(.flags))
        XCTAssertEqual(try attributes(of: item).flags, UInt32(UF_HIDDEN))
        XCTAssertEqual(try cipherStat("f").st_flags, UInt32(UF_HIDDEN | UF_TRACKED))

        let clear = FSItem.SetAttributesRequest()
        clear.flags = 0
        try setAttributes(clear, on: item)
        XCTAssertEqual(try cipherStat("f").st_flags, UInt32(UF_TRACKED), "clearing flags removed the ciphertext file's own flag")
    }

    /// An immutable item refuses other changes, so locking goes last and unlocking first.
    func testImmutableFlagIsSetLastAndClearedFirst() throws {
        let item = try create("f")
        let cipherPath = try XCTUnwrap(engine.cipherPath("f"))
        defer { chflags(cipherPath, 0) }

        let lock = FSItem.SetAttributesRequest()
        lock.flags = UInt32(UF_IMMUTABLE)
        lock.modifyTime = time(1_577_934_245)
        try setAttributes(lock, on: item)
        XCTAssertEqual(try attributes(of: item).flags, UInt32(UF_IMMUTABLE))

        let unlock = FSItem.SetAttributesRequest()
        unlock.flags = 0
        unlock.modifyTime = time(1_600_000_000)
        try setAttributes(unlock, on: item)
        let attrs = try attributes(of: item)
        XCTAssertEqual(attrs.flags, 0)
        assertTime(attrs.modifyTime, 1_600_000_000, 0, "modify time set together with unlocking")
    }

    func testOwnershipIsAppliedOrRefused() throws {
        let item = try create("f")
        var groups = [gid_t](repeating: 0, count: Int(NGROUPS_MAX))
        let count = getgroups(Int32(groups.count), &groups)
        XCTAssertGreaterThan(count, 0)
        let current = try cipherStat("f").st_gid
        let other = try XCTUnwrap(groups.prefix(Int(count)).first { $0 != current }, "no second group to test with")

        let regroup = FSItem.SetAttributesRequest()
        regroup.gid = other
        try setAttributes(regroup, on: item)
        XCTAssertTrue(regroup.wasAttributeConsumed(.gid))
        XCTAssertEqual(try cipherStat("f").st_gid, other, "chgrp to one of our groups was dropped")

        try XCTSkipIf(getuid() == 0, "root may give files away")
        let giveAway = FSItem.SetAttributesRequest()
        giveAway.uid = 0
        XCTAssertThrowsError(try setAttributes(giveAway, on: item)) { XCTAssertEqual(self.posixCode($0), .EPERM) }
    }

    /// FSKit: ignore the size of a directory, without an error.
    func testSizeOfADirectoryIsIgnored() throws {
        let dir = try create("d", type: .directory)
        let request = FSItem.SetAttributesRequest()
        request.size = 0
        XCTAssertNoThrow(try setAttributes(request, on: dir))
        XCTAssertFalse(request.wasAttributeConsumed(.size))
    }

    /// A removed item that is still open keeps its own file; the name may already
    /// belong to a successor.
    func testChangesToAnUnlinkedItemStayOnItsOwnFile() throws {
        let old = try create("f")
        try open(old, [.read, .write])
        defer { try? close(old) }
        try remove(old)
        let successor = try create("f")

        let request = FSItem.SetAttributesRequest()
        request.mode = 0o600
        request.modifyTime = time(1_577_934_245)
        try setAttributes(request, on: old)

        let successorAttrs = try attributes(of: successor)
        XCTAssertEqual(successorAttrs.mode, 0o644, "a change to the removed item landed on its successor")
        let oldAttrs = try attributes(of: old)
        XCTAssertEqual(oldAttrs.mode, 0o600)
        assertTime(oldAttrs.modifyTime, 1_577_934_245, 0, "modify time of the removed item")
    }

    /// Times and flags act on the entry itself, never on the target of a symlink
    /// planted in the ciphertext directory.
    func testChangesDoNotFollowPlantedSymlink() throws {
        let item = try create("f")
        let outside = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data("outside the vault".utf8).write(to: outside)
        defer { try? FileManager.default.removeItem(at: outside) }
        var before = stat()
        XCTAssertEqual(lstat(outside.path, &before), 0)

        let cipherPath = try XCTUnwrap(engine.cipherPath("f"))
        try FileManager.default.removeItem(atPath: cipherPath)
        try FileManager.default.createSymbolicLink(atPath: cipherPath, withDestinationPath: outside.path)

        let request = FSItem.SetAttributesRequest()
        request.modifyTime = time(1_577_934_245)
        request.flags = UInt32(UF_HIDDEN)
        try? setAttributes(request, on: item)
        var after = stat()
        XCTAssertEqual(lstat(outside.path, &after), 0)
        XCTAssertEqual(after.st_mtimespec.tv_sec, before.st_mtimespec.tv_sec, "utimes followed a symlink out of the vault")
        XCTAssertEqual(after.st_flags, before.st_flags, "chflags followed a symlink out of the vault")
    }
}
