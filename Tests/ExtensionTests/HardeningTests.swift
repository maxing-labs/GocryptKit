import Foundation
import FSKit
import VaultCore
import XCTest

final class HardeningTests: VolumeTestCase {

    private func reclaim(_ item: GocryptfsItem) {
        volume.reclaimItem(item) { _ in }
    }

    private func setMode(_ mode: UInt32, on item: GocryptfsItem) throws {
        let request = FSItem.SetAttributesRequest()
        request.mode = mode
        var result: Result<FSItem.Attributes, Error>?
        volume.setAttributes(request, on: item) { attrs, error in
            result = attrs.map { .success($0) } ?? .failure(error ?? POSIXError(.EIO))
        }
        _ = try XCTUnwrap(result).get()
    }

    /// F-12: reclaiming a removed item must not evict the item that now owns its path.
    func testReclaimOfRemovedItemKeepsItsSuccessorCached() throws {
        let old = try create("f")
        try remove(old)
        let successor = try create("f")
        reclaim(old)
        XCTAssertTrue(try lookup("f") === successor, "reclaim of the old item evicted its successor")
    }

    /// I-1: failures carry their real errno instead of a blanket EIO.
    func testMutationsReportRealErrno() throws {
        let dir = try create("d", type: .directory)
        XCTAssertThrowsError(try create("d", type: .directory)) { XCTAssertEqual(self.posixCode($0), .EEXIST) }
        _ = try create("child", in: dir)
        XCTAssertThrowsError(try remove(dir)) { XCTAssertEqual(self.posixCode($0), .ENOTEMPTY) }
        let ghost = GocryptfsItem(id: .invalid, plainPath: "ghost", name: "ghost", itemType: .file, inode: 99)
        XCTAssertThrowsError(try remove(ghost)) { XCTAssertEqual(self.posixCode($0), .ENOENT) }
    }

    /// I-1: a failed truncate or write reports its errno instead of EIO.
    func testTruncateAndWriteFailuresReportErrno() throws {
        let item = try create("f")
        try open(item, [.read, .write])
        defer { try? close(item) }

        var saved = rlimit()
        XCTAssertEqual(getrlimit(RLIMIT_FSIZE, &saved), 0)
        var lowered = saved
        lowered.rlim_cur = 1 << 20
        signal(SIGXFSZ, SIG_IGN)
        XCTAssertEqual(setrlimit(RLIMIT_FSIZE, &lowered), 0)
        defer {
            setrlimit(RLIMIT_FSIZE, &saved)
            signal(SIGXFSZ, SIG_DFL)
        }

        let request = FSItem.SetAttributesRequest()
        request.size = 4 << 20
        XCTAssertThrowsError(try setAttributes(request, on: item)) { XCTAssertEqual(self.posixCode($0), .EFBIG) }
        XCTAssertThrowsError(try write("x", to: item, at: 3 << 20)) { XCTAssertEqual(self.posixCode($0), .EFBIG) }
    }

    /// I-1: an open that the backing file refuses reports why.
    func testOpenFailureReportsErrno() throws {
        let item = try create("f")
        try open(item, [.write])
        try close(item)  // an existing file from here on
        let cipherPath = try XCTUnwrap(engine.cipherPath("f"))
        XCTAssertEqual(chflags(cipherPath, UInt32(UF_IMMUTABLE)), 0)
        defer { chflags(cipherPath, 0) }
        XCTAssertThrowsError(try open(item, [.read, .write])) { XCTAssertEqual(self.posixCode($0), .EPERM) }
    }

    /// P-2: a refused read open reports why. It was ENOENT for a file that
    /// exists, which backup tools take for a file deleted mid-run.
    func testReadOpenFailureReportsErrno() throws {
        let item = try create("f")
        try open(item, [.write])
        try close(item)  // an existing file from here on
        let cipherPath = try XCTUnwrap(engine.cipherPath("f"))
        XCTAssertEqual(chmod(cipherPath, 0), 0)
        defer { chmod(cipherPath, 0o600) }
        XCTAssertThrowsError(try open(item, [.read])) { XCTAssertEqual(self.posixCode($0), .EACCES) }
    }

    /// F-11: chmod acts on the item itself, never on the target of a symlink
    /// planted in the ciphertext directory.
    func testSetModeDoesNotFollowPlantedSymlink() throws {
        let item = try create("f")
        try setMode(0o600, on: item)
        XCTAssertEqual(try attributes(of: item).mode, 0o600)

        let outside = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data("outside the vault".utf8).write(to: outside)
        defer { try? FileManager.default.removeItem(at: outside) }
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: outside.path)

        let cipherPath = try XCTUnwrap(engine.cipherPath("f"))
        try FileManager.default.removeItem(atPath: cipherPath)
        try FileManager.default.createSymbolicLink(atPath: cipherPath, withDestinationPath: outside.path)

        try? setMode(0o777, on: item)
        let mode = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: outside.path)[.posixPermissions] as? NSNumber)
        XCTAssertEqual(mode.intValue, 0o644, "chmod followed a symlink out of the vault")
    }
}
