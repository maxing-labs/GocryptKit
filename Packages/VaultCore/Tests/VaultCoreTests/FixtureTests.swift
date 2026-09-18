import XCTest
@testable import VaultCore

final class FixtureTests: XCTestCase {
    var fixturesDir: URL {
        // Find Tests/fixtures relative to #file
        let currentFile = URL(fileURLWithPath: #file)
        let root = currentFile
            .deletingLastPathComponent() // VaultCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // VaultCore
            .deletingLastPathComponent() // Packages
            .deletingLastPathComponent() // GocryptKit
        return root.appendingPathComponent("Tests/fixtures")
    }

    func verifyStandardFixture(version: String) throws {
        let vaultURL = fixturesDir.appendingPathComponent(version)
        guard FileManager.default.fileExists(atPath: vaultURL.appendingPathComponent("gocryptfs.conf").path) else {
            XCTFail("Fixture gocryptfs.conf not found at \(vaultURL.path)")
            return
        }

        var returnedHash: Data? = nil
        let engine = try GocryptfsEngine(cipherDir: vaultURL, credential: .password("test"), returnedScryptHash: &returnedHash)
        defer { engine.shutdown() }

        XCTAssertNotNil(returnedHash, "Should return scrypt hash for caching")
        XCTAssertEqual(returnedHash?.count, 32)

        // 1. List files
        let entries = try engine.list("/")
        let names = Set(entries.map { $0.name })
        XCTAssertTrue(names.contains("status.txt"), "\(version) should contain status.txt")

        // 2. Read status.txt
        let handle = try engine.open("status.txt")
        defer { engine.close(handle) }

        var buffer = [UInt8](repeating: 0, count: 64)
        let bytesRead = try buffer.withUnsafeMutableBytes {
            try engine.read(handle, offset: 0, into: $0)
        }
        let content = String(decoding: buffer[0..<bytesRead], as: UTF8.self)
        XCTAssertEqual(content, "It works!\n", "\(version) status.txt content mismatch")

        // 3. Read rel symlink
        if names.contains("rel") {
            let relTarget = try engine.readlink("rel")
            XCTAssertEqual(relTarget, "status.txt", "\(version) rel symlink mismatch")
        }

        // 4. Read abs symlink
        if names.contains("abs") {
            let absTarget = try engine.readlink("abs")
            XCTAssertEqual(absTarget, "/a/b/c/d", "\(version) abs symlink mismatch")
        }

        // 5. Test cipherPath
        let cPath = engine.cipherPath("status.txt")
        XCTAssertNotNil(cPath, "\(version) cipherPath should not be nil")
        if let cPath = cPath {
            XCTAssertTrue(FileManager.default.fileExists(atPath: cPath), "Ciphertext file \(cPath) should exist on disk")
        }

        // 6. Test unlock using scryptHash
        if let hash = returnedHash {
            let hashEngine = try GocryptfsEngine(cipherDir: vaultURL, credential: .scryptHash(hash))
            defer { hashEngine.shutdown() }
            let h = try hashEngine.open("status.txt")
            defer { hashEngine.close(h) }
            var b = [UInt8](repeating: 0, count: 64)
            let n = try b.withUnsafeMutableBytes {
                try hashEngine.read(h, offset: 0, into: $0)
            }
            let s = String(decoding: b[0..<n], as: UTF8.self)
            XCTAssertEqual(s, "It works!\n")
        }
    }

    func testV1_3_Default() throws {
        try verifyStandardFixture(version: "v1.3")
    }

    func testV0_9_Longnames() throws {
        try verifyStandardFixture(version: "v0.9")

        // Verify longname file specifically
        let vaultURL = fixturesDir.appendingPathComponent("v0.9")
        let engine = try GocryptfsEngine(cipherDir: vaultURL, credential: .password("test"))
        defer { engine.shutdown() }

        let entries = try engine.list("/")
        let longnames = entries.filter { $0.name.hasPrefix("longname_255_") }
        XCTAssertFalse(longnames.isEmpty, "v0.9 should have a longname_255_ file")

        if let longnameEntry = longnames.first {
            let h = try engine.open(longnameEntry.name)
            defer { engine.close(h) }
            var buf = [UInt8](repeating: 0, count: 64)
            let n = try buf.withUnsafeMutableBytes {
                try engine.read(h, offset: 0, into: $0)
            }
            let text = String(decoding: buf[0..<n], as: UTF8.self)
            XCTAssertEqual(text, "It works!\n")
        }
    }

    func testV2_2_XChaCha() throws {
        try verifyStandardFixture(version: "v2.2-xchacha")
    }

    func testV1_1_AESSIV() throws {
        try verifyStandardFixture(version: "v1.1-aessiv")
    }

    func testV2_2_DeterministicNames() throws {
        try verifyStandardFixture(version: "v2.2-deterministic-names")
    }

    func testWrongPassword() throws {
        let vaultURL = fixturesDir.appendingPathComponent("v1.3")
        XCTAssertThrowsError(try GocryptfsEngine(cipherDir: vaultURL, credential: .password("wrong_password"))) { error in
            XCTAssertEqual(error as? VaultError, .authFailed)
        }
    }
}
