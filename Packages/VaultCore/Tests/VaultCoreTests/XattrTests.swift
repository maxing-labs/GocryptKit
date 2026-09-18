import XCTest
@testable import VaultCore

final class XattrTests: XCTestCase {
    private static let fastLogN: Int32 = 10

    private var cipherDir: URL!
    private var engine: GocryptfsEngine!

    override func setUpWithError() throws {
        cipherDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("gocryptfs-xattr-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: cipherDir, withIntermediateDirectories: true)
        try GocryptfsEngine.createVault(at: cipherDir, password: "xattr-pw", scryptLogN: Self.fastLogN)
        engine = try GocryptfsEngine(cipherDir: cipherDir, credential: .password("xattr-pw"))

        let h = try engine.openWrite("file.txt")
        _ = try Data("body\n".utf8).withUnsafeBytes { try engine.write(h, offset: 0, from: $0) }
        engine.close(h)
    }

    override func tearDownWithError() throws {
        engine?.shutdown()
        if let dir = cipherDir { try? FileManager.default.removeItem(at: dir) }
    }

    func testRoundTrip() throws {
        let value = Data("0081;00000000;Safari;".utf8)
        try engine.setXattr("file.txt", named: "com.apple.quarantine", to: value)
        XCTAssertEqual(try engine.getXattr("file.txt", named: "com.apple.quarantine"), value)
        XCTAssertEqual(try engine.listXattrs("file.txt"), ["com.apple.quarantine"])
    }

    func testMultipleAttributesAndRemoval() throws {
        try engine.setXattr("file.txt", named: "com.apple.provenance", to: Data([1, 2, 3]))
        try engine.setXattr("file.txt", named: "com.apple.metadata:_kMDItemUserTags",
                            to: Data("红色\n".utf8))
        XCTAssertEqual(Set(try engine.listXattrs("file.txt")),
                       ["com.apple.provenance", "com.apple.metadata:_kMDItemUserTags"])

        try engine.removeXattr("file.txt", named: "com.apple.provenance")
        XCTAssertEqual(try engine.listXattrs("file.txt"), ["com.apple.metadata:_kMDItemUserTags"])
        XCTAssertThrowsError(try engine.getXattr("file.txt", named: "com.apple.provenance"))
    }

    func testEmptyValueIsPreserved() throws {
        // com.apple.provenance often carries an empty value; this path must succeed —
        // otherwise every file with an automatically attached xattr would fail.
        try engine.setXattr("file.txt", named: "com.apple.provenance", to: Data())
        XCTAssertEqual(try engine.getXattr("file.txt", named: "com.apple.provenance"), Data())
        XCTAssertEqual(try engine.listXattrs("file.txt"), ["com.apple.provenance"])
    }

    func testValueUpToTheLimit() throws {
        let big = Data(repeating: 0xAB, count: GocryptfsEngine.maximumXattrValueSize)
        try engine.setXattr("file.txt", named: "big", to: big)
        XCTAssertEqual(try engine.getXattr("file.txt", named: "big"), big)

        let tooBig = Data(repeating: 0xAB, count: GocryptfsEngine.maximumXattrValueSize + 1)
        XCTAssertThrowsError(try engine.setXattr("file.txt", named: "big2", to: tooBig)) {
            XCTAssertEqual($0 as? VaultError, .ioError(E2BIG))
        }
    }

    func testWritePolicies() throws {
        XCTAssertThrowsError(
            try engine.setXattr("file.txt", named: "k", to: Data([1]), policy: .mustReplace),
            "mustReplace should fail when attribute does not exist")

        try engine.setXattr("file.txt", named: "k", to: Data([1]), policy: .mustCreate)
        XCTAssertThrowsError(
            try engine.setXattr("file.txt", named: "k", to: Data([2]), policy: .mustCreate),
            "mustCreate should fail when attribute already exists")

        try engine.setXattr("file.txt", named: "k", to: Data([3]), policy: .mustReplace)
        XCTAssertEqual(try engine.getXattr("file.txt", named: "k"), Data([3]))
    }

    func testDirectoriesAndRootCarryXattrs() throws {
        try engine.mkdir("sub")
        try engine.setXattr("sub", named: "on-dir", to: Data("d".utf8))
        try engine.setXattr("/", named: "on-root", to: Data("r".utf8))
        XCTAssertEqual(try engine.getXattr("sub", named: "on-dir"), Data("d".utf8))
        XCTAssertEqual(try engine.getXattr("/", named: "on-root"), Data("r".utf8))
        // Directory xattrs must not bleed into files inside.
        XCTAssertEqual(try engine.listXattrs("file.txt"), [])
    }

    /// The raison d'être for this feature: neither name nor value must land in plaintext in the ciphertext directory.
    func testNeitherNameNorValueLandsInPlaintext() throws {
        try engine.setXattr("file.txt", named: "com.apple.metadata:kMDItemWhereFroms",
                            to: Data("https://secret.example.com/report.pdf".utf8))

        let cipherFile = try XCTUnwrap(engine.cipherPath("file.txt"))
        let raw = try XCTUnwrap(rawXattrs(of: cipherFile))

        // Note: the ciphertext file itself also receives an automatically assigned com.apple.provenance from macOS;
        // that is attached by APFS to the ciphertext file and unrelated to payload contents, hence not a leak.
        // What we must verify is that our stored attribute name does not appear in any form.
        XCTAssertFalse(raw.names.contains { $0.contains("WhereFroms") || $0.contains("kMDItem") },
                       "xattr name persisted to disk in plaintext: \(raw.names)")
        XCTAssertEqual(raw.names.filter { $0.hasPrefix("user.gocryptfs.") }.count, 1,
                       "Expected exactly one user.gocryptfs.* entry, got: \(raw.names)")
        for (name, blob) in zip(raw.names, raw.values) where name.hasPrefix("user.gocryptfs.") {
            XCTAssertNil(String(data: blob, encoding: .utf8)?.range(of: "secret.example.com"),
                         "xattr value persisted to disk in plaintext")
        }
    }

    func testForeignXattrsAreIgnored() throws {
        // Writing an xattr directly on the ciphertext file that does not match our format
        // should not appear in listings, nor cause listXattrs to fail entirely.
        let cipherFile = try XCTUnwrap(engine.cipherPath("file.txt"))
        XCTAssertEqual(setxattr(cipherFile, "com.example.foreign", [1, 2, 3], 3, 0, XATTR_NOFOLLOW), 0)

        try engine.setXattr("file.txt", named: "ours", to: Data([9]))
        XCTAssertEqual(try engine.listXattrs("file.txt"), ["ours"])
    }

    func testOverlyLongNameIsRejectedNotTruncated() throws {
        // Encrypted names expand ~1.8x; exceeding XATTR_MAXNAMELEN(127) must be rejected.
        // Rejection is correct: silent truncation would cause two different attributes to overwrite each other.
        let longName = String(repeating: "a", count: 100)
        XCTAssertThrowsError(try engine.setXattr("file.txt", named: longName, to: Data([1]))) {
            XCTAssertEqual($0 as? VaultError, .ioError(ENAMETOOLONG))
        }
    }

    func testXattrsSurviveRemount() throws {
        try engine.setXattr("file.txt", named: "persist", to: Data("kept".utf8))
        engine.shutdown()

        engine = try GocryptfsEngine(cipherDir: cipherDir, credential: .password("xattr-pw"))
        XCTAssertEqual(try engine.getXattr("file.txt", named: "persist"), Data("kept".utf8))
    }

    // MARK: -

    /// Bypasses the engine to directly read raw xattrs on the ciphertext file.
    private func rawXattrs(of path: String) -> (names: [String], values: [Data])? {
        let size = listxattr(path, nil, 0, XATTR_NOFOLLOW)
        guard size > 0 else { return ([], []) }
        var buf = [CChar](repeating: 0, count: size)
        guard listxattr(path, &buf, size, XATTR_NOFOLLOW) == size else { return nil }

        let names = buf.split(separator: 0, omittingEmptySubsequences: true)
            .map { String(decoding: $0.map { UInt8(bitPattern: $0) }, as: UTF8.self) }
        let values: [Data] = names.map { name in
            let vSize = getxattr(path, name, nil, 0, 0, XATTR_NOFOLLOW)
            guard vSize > 0 else { return Data() }
            var v = [UInt8](repeating: 0, count: vSize)
            _ = getxattr(path, name, &v, vSize, 0, XATTR_NOFOLLOW)
            return Data(v)
        }
        return (names, values)
    }
}
