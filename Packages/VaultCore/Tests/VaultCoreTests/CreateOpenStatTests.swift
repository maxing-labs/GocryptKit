import XCTest
import VaultCore

/// F-8 building blocks: exclusive create, open-without-create and fd-based attributes.
final class CreateOpenStatTests: XCTestCase {
    private var directory: URL!
    private var engine: GocryptfsEngine!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let password = UUID().uuidString
        _ = try GocryptfsEngine.createVault(at: directory, password: password, scryptLogN: 10)
        engine = try GocryptfsEngine(cipherDir: directory, credential: .password(password))
    }

    override func tearDownWithError() throws {
        engine?.shutdown()
        try FileManager.default.removeItem(at: directory)
    }

    private func write(_ h: Int32, _ text: String) throws {
        let data = Data(text.utf8)
        XCTAssertEqual(try data.withUnsafeBytes { try engine.write(h, offset: 0, from: $0) }, data.count)
    }

    func testCreateFileIsExclusive() throws {
        let h = try engine.createFile("lock")
        try write(h, "owner")
        engine.close(h)
        XCTAssertThrowsError(try engine.createFile("lock")) { error in
            XCTAssertEqual(error as? VaultError, .posix(EEXIST))
        }
        XCTAssertEqual(try engine.stat("lock").size, 5)
    }

    func testOpenWriteExistingNeverCreates() throws {
        XCTAssertThrowsError(try engine.openWriteExisting("gone")) { error in
            XCTAssertEqual(error as? VaultError, .posix(ENOENT))
        }
        XCTAssertThrowsError(try engine.stat("gone"))
        engine.close(try engine.createFile("gone"))
        engine.close(try engine.openWriteExisting("gone"))
    }

    func testStatReportsPlaintextSizeAndType() throws {
        try engine.mkdir("d")
        let h = try engine.createFile("d/f", mode: 0o600)
        try write(h, "twelve bytes")
        engine.close(h)
        let file = try engine.stat("d/f")
        XCTAssertEqual(file.size, 12)
        XCTAssertEqual(file.mode & 0o777, 0o600)
        XCTAssertFalse(file.isDirectory)
        XCTAssertEqual(file.linkCount, 1)
        XCTAssertTrue(try engine.stat("d").isDirectory)
        XCTAssertTrue(try engine.stat("").isDirectory)
        XCTAssertThrowsError(try engine.stat("d/missing")) { error in
            XCTAssertEqual(error as? VaultError, .posix(ENOENT))
        }
        XCTAssertThrowsError(try engine.stat("missing-dir/f"))
    }

    func testStatByHandleSurvivesUnlink() throws {
        let h = try engine.createFile("f")
        try write(h, "hello")
        let inode = try engine.stat("f").inode
        try engine.remove("f")
        let unlinked = try engine.stat(handle: h)
        XCTAssertEqual(unlinked.size, 5)
        XCTAssertEqual(unlinked.inode, inode)
        XCTAssertEqual(unlinked.linkCount, 0)
        engine.close(h)
        XCTAssertThrowsError(try engine.stat(handle: h))
    }
}

/// I-1 / I-3 through the C ABI.
final class EngineErrnoTests: XCTestCase {
    private func makeVault() throws -> (URL, String) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let password = UUID().uuidString
        _ = try GocryptfsEngine.createVault(at: directory, password: password, scryptLogN: 10)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        return (directory, password)
    }

    func testMutationsReportRealErrno() throws {
        let (directory, password) = try makeVault()
        let engine = try GocryptfsEngine(cipherDir: directory, credential: .password(password))
        defer { engine.shutdown() }
        try engine.mkdir("d")
        engine.close(try engine.createFile("d/f"))
        XCTAssertThrowsError(try engine.mkdir("d")) { XCTAssertEqual($0 as? VaultError, .posix(EEXIST)) }
        XCTAssertThrowsError(try engine.rmdir("d")) { XCTAssertEqual($0 as? VaultError, .posix(ENOTEMPTY)) }
        XCTAssertThrowsError(try engine.remove("missing")) { XCTAssertEqual($0 as? VaultError, .posix(ENOENT)) }
        XCTAssertThrowsError(try engine.rename(from: "missing", to: "x")) { XCTAssertEqual($0 as? VaultError, .posix(ENOENT)) }
        try engine.chmod("d/f", mode: 0o600)
        XCTAssertEqual(try engine.stat("d/f").mode & 0o777, 0o600)
        XCTAssertThrowsError(try engine.chmod("missing", mode: 0o600))
    }

    /// A-2: openWrite (tests, vaultctl, iOS) said "not found" to every failure.
    func testOpenWriteReportsRealErrno() throws {
        let (directory, password) = try makeVault()
        let engine = try GocryptfsEngine(cipherDir: directory, credential: .password(password))
        defer { engine.shutdown() }
        try engine.mkdir("ro")
        let cipherPath = try XCTUnwrap(engine.cipherPath("ro"))
        XCTAssertEqual(chmod(cipherPath, 0o500), 0)
        defer { chmod(cipherPath, 0o700) }
        XCTAssertThrowsError(try engine.openWrite("ro/new")) { XCTAssertEqual($0 as? VaultError, .posix(EACCES)) }
        XCTAssertThrowsError(try engine.openWrite("missing/new")) {
            XCTAssertEqual($0 as? VaultError, .posix(ENOENT))
        }
    }

    /// A callback that arrives after its volume was unmounted must not reach
    /// the volume that was mounted next.
    func testClosedEngineCannotReachTheNextVolume() throws {
        let (firstDir, firstPassword) = try makeVault()
        let (secondDir, secondPassword) = try makeVault()
        let first = try GocryptfsEngine(cipherDir: firstDir, credential: .password(firstPassword))
        first.shutdown()
        let second = try GocryptfsEngine(cipherDir: secondDir, credential: .password(secondPassword))
        defer { second.shutdown() }
        XCTAssertNotEqual(first.volumeID, second.volumeID)
        XCTAssertThrowsError(try first.openWrite("stray"))
        XCTAssertThrowsError(try second.stat("stray"), "a closed engine created a file in another vault")
    }
}
