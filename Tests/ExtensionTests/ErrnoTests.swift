import Foundation
import FSKit
import ObjectiveC
import VaultCore
import XCTest

/// A-2: callbacks report the errno the engine saw. read, readSymbolicLink and
/// enumerateDirectory answered EIO to every failure, the xattr callbacks lost
/// ENOENT.
final class ErrnoTests: VolumeTestCase {

    /// The errno of a callback's reply, as a number so that a failure shows it.
    private func code(_ error: Error) -> Int32? {
        (error as? POSIXError)?.code.rawValue
    }

    private func enumerate(_ directory: GocryptfsItem) throws {
        var error: Error?
        volume.enumerateDirectory(directory, startingAt: FSDirectoryCookie(0), verifier: FSDirectoryVerifier(0),
                                  attributes: nil, packer: BatchPacker.make(room: 100)) { _, e in error = e }
        if let error { throw error }
    }

    func testEnumeratingAVanishedDirectoryReportsENOENT() throws {
        let dir = try create("d", type: .directory)
        try engine.rmdir("d")  // removed underneath, as a sync client does
        XCTAssertThrowsError(try enumerate(dir)) { XCTAssertEqual(self.code($0), ENOENT) }
    }

    func testEnumeratingAnUnreadableDirectoryReportsEACCES() throws {
        let dir = try create("d", type: .directory)
        let cipherPath = try XCTUnwrap(engine.cipherPath("d"))
        XCTAssertEqual(chmod(cipherPath, 0), 0)
        defer { chmod(cipherPath, 0o700) }
        XCTAssertThrowsError(try enumerate(dir)) { XCTAssertEqual(self.code($0), EACCES) }
    }

    func testReadingAVanishedSymlinkReportsENOENT() throws {
        // The extension cannot create symlinks; an item whose entry is gone
        // underneath takes the same path through the engine.
        let link = GocryptfsItem(id: .invalid, plainPath: "link", name: "link", itemType: .symlink, inode: 99)
        var error: Error?
        volume.readSymbolicLink(link) { _, e in error = e }
        XCTAssertEqual(code(try XCTUnwrap(error)), ENOENT)
    }

    func testReadThatCannotOpenReportsItsErrno() throws {
        let item = try create("f")
        try open(item, [.write])
        try write("x", to: item)
        try close(item)  // no handle left, so read opens one by path
        let cipherPath = try XCTUnwrap(engine.cipherPath("f"))
        XCTAssertEqual(chmod(cipherPath, 0), 0)
        defer { chmod(cipherPath, 0o600) }
        // The open fails before the buffer is touched; FSMutableFileDataBuffer
        // has no public initializer.
        let buffer = class_createInstance(FSMutableFileDataBuffer.self, 0) as! FSMutableFileDataBuffer
        var error: Error?
        volume.read(from: item, at: 0, length: 1, into: buffer) { _, e in error = e }
        XCTAssertEqual(code(try XCTUnwrap(error)), EACCES)
    }

    func testXattrsOfARemovedItemReportENOENT() throws {
        let item = try create("f")
        try open(item, [.write])
        try close(item)
        try remove(item)  // no handle left to reach the unlinked file through
        var errors: [String: Error?] = [:]
        volume.getXattr(named: FSFileName(string: "user.x"), of: item) { _, e in errors["get"] = e }
        volume.setXattr(named: FSFileName(string: "user.x"), to: Data("v".utf8), on: item,
                        policy: .alwaysSet) { errors["set"] = $0 }
        volume.listXattrs(of: item) { _, e in errors["list"] = e }
        for (call, error) in errors {
            XCTAssertEqual(code(try XCTUnwrap(error, call)), ENOENT, call)
        }
        XCTAssertEqual(errors.count, 3)
    }
}
