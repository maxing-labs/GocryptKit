import Foundation
import FSKit
import VaultCore
import XCTest

/// F-8 and the incomplete-attributes fault: what happens to an item after it
/// was removed or replaced while FSKit still holds it.
final class UnlinkSemanticsTests: VolumeTestCase {

    func testCreateItemIsExclusive() throws {
        let first = try create("lock")
        try open(first, [.write])
        try write("owner", to: first)
        try close(first)
        XCTAssertThrowsError(try create("lock")) { error in
            XCTAssertEqual(self.posixCode(error), .EEXIST)
        }
        XCTAssertEqual(try content(of: "lock"), "owner")
    }

    func testWriteAfterRemoveDoesNotResurrectFile() throws {
        let item = try create("f")
        try open(item, [.write])
        try write("before", to: item)
        try remove(item)
        XCTAssertFalse(exists("f"))
        // The process still has the file open: its writes go to the unlinked inode.
        XCTAssertEqual(try write("after!", to: item), 6)
        XCTAssertFalse(exists("f"), "a write after unlink resurrected the file")
        try close(item)
    }

    func testLateWriteWithoutHandleDoesNotResurrectFile() throws {
        let item = try create("f")
        try open(item, [.write])
        try close(item)  // the creating open is over: no handle left
        try remove(item)
        XCTAssertThrowsError(try write("late", to: item))
        XCTAssertFalse(exists("f"), "a late write resurrected the file")
    }

    func testWriteAfterRenameOverLeavesReplacementAlone() throws {
        let victim = try create("a")
        try open(victim, [.write])
        try write("victim", to: victim)
        let replacement = try create("b")
        try open(replacement, [.write])
        try write("replacement", to: replacement)
        try close(replacement)
        try rename(replacement, to: "a", over: victim)
        // Writes to the replaced file must not land in the file that replaced it.
        _ = try? write("XXXXXX", to: victim, at: 8192)
        XCTAssertEqual(try content(of: "a"), "replacement")
        try close(victim)
        XCTAssertEqual(try content(of: "a"), "replacement")
    }

    func testRenamedOpenFileKeepsReceivingWrites() throws {
        let item = try create("f")
        try open(item, [.write])
        try write("one", to: item)
        try rename(item, to: "g")
        try write("two", to: item, at: 3)
        try close(item)
        XCTAssertEqual(try content(of: "g"), "onetwo")
        XCTAssertFalse(exists("f"))
    }

    func testGetAttributesAfterRemoveReportsENOENT() throws {
        let item = try create("f")
        try open(item, [.write])
        try close(item)  // no handle left
        XCTAssertEqual(try attributes(of: item).size, 0)
        try remove(item)
        // An empty attribute set makes FSKit fault ("attributes are incomplete") and return EINVAL.
        XCTAssertThrowsError(try attributes(of: item)) { error in
            XCTAssertEqual(self.posixCode(error), .ENOENT)
        }
    }

    func testGetAttributesOfUnlinkedOpenFileStillWorks() throws {
        let item = try create("f")
        try open(item, [.write])
        try write("hello", to: item)
        try remove(item)
        let attrs = try attributes(of: item)
        XCTAssertEqual(attrs.size, 5)
        XCTAssertEqual(attrs.linkCount, 0)
        try close(item)
    }

    /// F-11: xattr calls on a removed but still open item use its own file,
    /// not whatever took over the name.
    func testXattrsOfUnlinkedItemStayOnItsOwnFile() throws {
        let old = try create("f")
        try open(old, [.read, .write])
        defer { try? close(old) }
        try remove(old)
        _ = try create("f")

        var error: Error?
        volume.setXattr(named: FSFileName(string: "user.tag"), to: Data("old".utf8), on: old, policy: .alwaysSet) { error = $0 }
        XCTAssertNil(error)
        XCTAssertThrowsError(try engine.getXattr("f", named: "user.tag"), "the xattr landed on the successor")
        var value: Data?
        volume.getXattr(named: FSFileName(string: "user.tag"), of: old) { data, _ in value = data }
        XCTAssertEqual(value, Data("old".utf8))
    }

    /// A file created read-only (cp of a 0444 file, a new gocryptfs.conf) takes
    /// the writes of the open that created it: POSIX checks permissions on
    /// existing files only. Reopening it for writing by path is refused.
    func testFileCreatedReadOnlyTakesItsFirstWrites() throws {
        let readOnly = FSItem.SetAttributesRequest()
        readOnly.mode = 0o444
        let item = try create("ro", attributes: readOnly)
        try open(item, [.write])
        try write("content", to: item)
        try close(item)
        XCTAssertEqual(try content(of: "ro"), "content")
        XCTAssertEqual(try attributes(of: item).mode, 0o444)
    }

    /// R-4: a size change before the creating open borrows createItem's handle
    /// and gives it back. It used to close it, and the open was refused.
    func testSizeChangeBeforeTheCreatingOpenKeepsItsHandle() throws {
        let readOnly = FSItem.SetAttributesRequest()
        readOnly.mode = 0o444
        let item = try create("ro", attributes: readOnly)
        let size = FSItem.SetAttributesRequest()
        size.size = 0
        try setAttributes(size, on: item)
        try open(item, [.write])
        try write("content", to: item)
        try close(item)
        XCTAssertEqual(try content(of: "ro"), "content")
    }

    /// R-4: a file created without read permission (O_CREAT|O_RDWR, 0200) is
    /// read through the handle that created it; reopening it by path is refused.
    func testFileCreatedWriteOnlyOpensForReadingAndWriting() throws {
        let writeOnly = FSItem.SetAttributesRequest()
        writeOnly.mode = 0o200
        let item = try create("wo", attributes: writeOnly)
        try open(item, [.read, .write])
        try write("content", to: item)
        let lease = try item.acquireReadLease(using: engine)
        var data = Data(count: 64)
        let count = try data.withUnsafeMutableBytes { try engine.read(lease.handle, offset: 0, into: $0) }
        item.release(lease, using: engine)
        XCTAssertEqual(String(decoding: data.prefix(count), as: UTF8.self), "content")
        try close(item)
    }

    /// R-4: an item removed before its first open reports its attributes through
    /// the handle createItem keeps, as an open item would.
    func testItemRemovedBeforeItsFirstOpenKeepsItsAttributes() throws {
        let item = try create("gone")
        try remove(item)
        XCTAssertNoThrow(try attributes(of: item))
        try open(item, [.write])
        try write("x", to: item)
        XCTAssertEqual(try attributes(of: item).size, 1)
        try close(item)
    }

    /// R-5: a rename over an item and a chmod of that item race. The chmod must
    /// reach the replaced file (or fail), never the file that took its name. The
    /// window between the rename and marking the item was hit about once per
    /// thousand tries, so this repeats.
    func testChmodOfAnItemBeingReplacedNeverReachesItsSuccessor() throws {
        let mode = FSItem.SetAttributesRequest()
        mode.mode = 0o600
        let chmod = FSItem.SetAttributesRequest()
        chmod.mode = 0o700
        var hits = 0
        for i in 0..<3000 {
            let moved = try create("a\(i)"), replaced = try create("b\(i)")
            for item in [moved, replaced] {
                try open(item, [.write])
                try close(item)  // no handle left: the replaced item has only its path
                try setAttributes(mode, on: item)
            }
            DispatchQueue.concurrentPerform(iterations: 2) { k in
                if k == 0 {
                    try? self.rename(moved, to: "b\(i)", over: replaced)
                } else {
                    self.volume.setAttributes(chmod, on: replaced) { _, _ in }
                }
            }
            if try attributes(of: moved).mode == 0o700 { hits += 1 }
        }
        XCTAssertEqual(hits, 0, "a chmod of the replaced item changed its successor")
    }

    func testFileCreatedReadOnlyWithASizeIsCreated() throws {
        let request = FSItem.SetAttributesRequest()
        request.mode = 0o400
        request.size = 10
        let item = try create("sized", attributes: request)
        XCTAssertEqual(try attributes(of: item).size, 10)
    }
}
