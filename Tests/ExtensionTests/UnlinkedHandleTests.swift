import Foundation
import FSKit
import VaultCore
import XCTest

final class UnlinkedHandleTests: VolumeTestCase {

    /// A file that is open write-only and then unlinked can still be read back
    /// (the kernel reads for partial-page writes): the read borrows the writer.
    func testReadOfUnlinkedWriteOnlyFileBorrowsWriter() throws {
        let item = try create("f")
        try open(item, [.write])
        try write("hello", to: item)
        try remove(item)
        let lease = try item.acquireReadLease(using: engine)
        var data = Data(count: 16)
        let count = try data.withUnsafeMutableBytes { try engine.read(lease.handle, offset: 0, into: $0) }
        item.release(lease, using: engine)
        XCTAssertEqual(String(decoding: data.prefix(count), as: UTF8.self), "hello")
        // The borrowed reference is returned: the writer is still usable, then closes.
        XCTAssertEqual(try write("!", to: item, at: 5), 1)
        try close(item)
        XCTAssertThrowsError(try item.acquireReadLease(using: engine))
    }

    func testEnumerationSkipsEntriesThatVanish() throws {
        _ = try create("keep")
        XCTAssertNoThrow(try engine.stat("keep"))
        XCTAssertThrowsError(try engine.stat("missing")) { error in
            XCTAssertEqual(error as? VaultError, .posix(ENOENT))
        }
    }
}
