import XCTest
@testable import VaultCore

final class CreateVaultTests: XCTestCase {
    /// Always use the minimum scrypt cost in tests. The default logN=16 takes several seconds per derivation,
    /// whereas these test cases verify vault structure and error handling, unrelated to KDF cost.
    private static let fastLogN: Int32 = 10

    private var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("gocryptfs-init-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let dir = tempDir {
            // gocryptfs.conf / gocryptfs.diriv have 0400 permissions; deleting the directory itself is unaffected.
            try? FileManager.default.removeItem(at: dir)
        }
    }

    private func conf(_ dir: URL) -> URL { dir.appendingPathComponent("gocryptfs.conf") }
    private func dirIV(_ dir: URL) -> URL { dir.appendingPathComponent("gocryptfs.diriv") }

    // MARK: - Happy Path

    func testCreatesConfAndRootDirIV() throws {
        let hash = try GocryptfsEngine.createVault(
            at: tempDir, password: "correct horse battery", scryptLogN: Self.fastLogN)

        XCTAssertEqual(hash.count, 32, "Should return 32-byte scrypt hash")
        XCTAssertNotEqual(hash, Data(repeating: 0, count: 32), "scrypt hash should not be all zeros")

        let fm = FileManager.default
        XCTAssertTrue(fm.fileExists(atPath: conf(tempDir).path), "Missing gocryptfs.conf")
        XCTAssertTrue(fm.fileExists(atPath: dirIV(tempDir).path), "Missing root directory gocryptfs.diriv")

        let ivData = try Data(contentsOf: dirIV(tempDir))
        XCTAssertEqual(ivData.count, 16, "DirIV should be 16 bytes")

        // Neither file should be modified after creation; upstream enforces read-only permissions:
        // conf 0400 (owner-readable only, contains wrapped master key), diriv 0444.
        for (url, expected) in [(conf(tempDir), 0o400), (dirIV(tempDir), 0o444)] {
            let perms = try fm.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
            XCTAssertEqual(perms?.intValue, expected,
                           "\(url.lastPathComponent) permissions should be \(String(expected, radix: 8))")
        }

        // conf + diriv + one encrypted .fseventsd directory (see testFSEventsMarker),
        // with no leftover temporary files like .tmp.
        let leftovers = try fm.contentsOfDirectory(atPath: tempDir.path).sorted()
        XCTAssertEqual(leftovers.count, 3, "Unexpected residual files: \(leftovers)")
        XCTAssertTrue(leftovers.contains("gocryptfs.conf"))
        XCTAssertTrue(leftovers.contains("gocryptfs.diriv"))
        XCTAssertFalse(leftovers.contains { $0.hasSuffix(".tmp") })
    }

    /// New vault comes pre-configured with `.fseventsd/no_log`: without it, macOS `fseventsd` continuously writes
    /// change logs into the volume, syncing them downstream to other devices.
    func testFSEventsMarkerIsPreCreated() throws {
        try GocryptfsEngine.createVault(at: tempDir, password: "marker-pw", scryptLogN: Self.fastLogN)

        let engine = try GocryptfsEngine(cipherDir: tempDir, credential: .password("marker-pw"))
        defer { engine.shutdown() }

        XCTAssertEqual(try engine.list("/").map(\.name), [".fseventsd"])
        XCTAssertEqual(try engine.list(".fseventsd").map(\.name), ["no_log"])

        // Marker directory name must also be encrypted on disk.
        let onDisk = try FileManager.default.contentsOfDirectory(atPath: tempDir.path)
        XCTAssertFalse(onDisk.contains { $0.contains("fseventsd") },
                       "Marker directory name persisted in plaintext: \(onDisk)")
    }

    func testConfIsWellFormedAndNamesAreEncrypted() throws {
        try GocryptfsEngine.createVault(at: tempDir, password: "pw-structure", scryptLogN: Self.fastLogN)

        let json = try JSONSerialization.jsonObject(
            with: Data(contentsOf: conf(tempDir))) as? [String: Any]
        let flags = json?["FeatureFlags"] as? [String] ?? []
        XCTAssertTrue(flags.contains("DirIV"), "File names must be encrypted (requires DirIV)")
        XCTAssertTrue(flags.contains("EMENames"))
        XCTAssertTrue(flags.contains("HKDF"))
        XCTAssertFalse(flags.contains("PlaintextNames"), "Never create vaults with plaintext file names")

        let scrypt = json?["ScryptObject"] as? [String: Any]
        XCTAssertEqual(scrypt?["N"] as? Int, 1 << Int(Self.fastLogN))
        XCTAssertEqual(scrypt?["R"] as? Int, 8)
        XCTAssertEqual(scrypt?["P"] as? Int, 1)
        XCTAssertEqual((scrypt?["Salt"] as? String).flatMap { Data(base64Encoded: $0) }?.count, 32)
    }

    func testDefaultScryptLogNIsSixteen() throws {
        // Default cost must not be inadvertently lowered: run this test with real default value even if slower.
        try GocryptfsEngine.createVault(at: tempDir, password: "pw-default-cost")
        let json = try JSONSerialization.jsonObject(
            with: Data(contentsOf: conf(tempDir))) as? [String: Any]
        let scrypt = json?["ScryptObject"] as? [String: Any]
        XCTAssertEqual(scrypt?["N"] as? Int, 1 << 16)
    }

    func testEveryVaultGetsItsOwnMasterKey() throws {
        let other = tempDir.appendingPathComponent("second")
        try FileManager.default.createDirectory(at: other, withIntermediateDirectories: true)

        try GocryptfsEngine.createVault(at: other, password: "same-password", scryptLogN: Self.fastLogN)
        let a = try JSONSerialization.jsonObject(with: Data(contentsOf: conf(other))) as? [String: Any]

        let third = FileManager.default.temporaryDirectory
            .appendingPathComponent("gocryptfs-init-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: third, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: third) }
        try GocryptfsEngine.createVault(at: third, password: "same-password", scryptLogN: Self.fastLogN)
        let b = try JSONSerialization.jsonObject(with: Data(contentsOf: conf(third))) as? [String: Any]

        XCTAssertNotEqual(a?["EncryptedKey"] as? String, b?["EncryptedKey"] as? String)
        let saltA = (a?["ScryptObject"] as? [String: Any])?["Salt"] as? String
        let saltB = (b?["ScryptObject"] as? [String: Any])?["Salt"] as? String
        XCTAssertNotEqual(saltA, saltB, "The scrypt salts for two separate vaults must differ")
    }

    // MARK: - Usable After Creation

    func testNewVaultRoundTrips() throws {
        try GocryptfsEngine.createVault(at: tempDir, password: "round-trip-pw", scryptLogN: Self.fastLogN)

        let payload = Data("新建卷的第一段内容 / first bytes\n".utf8)
        do {
            let engine = try GocryptfsEngine(cipherDir: tempDir, credential: .password("round-trip-pw"))
            defer { engine.shutdown() }

            // New vault contains nothing except the pre-created .fseventsd marker
            XCTAssertEqual(try engine.list("/").map(\.name), [".fseventsd"])

            try engine.mkdir("notes")
            let handle = try engine.openWrite("notes/hello.txt")
            let written = try payload.withUnsafeBytes { try engine.write(handle, offset: 0, from: $0) }
            engine.close(handle)
            XCTAssertEqual(written, payload.count)
        }

        // Re-open to confirm data was genuinely persisted to disk, not merely held in memory.
        let engine = try GocryptfsEngine(cipherDir: tempDir, credential: .password("round-trip-pw"))
        defer { engine.shutdown() }
        let handle = try engine.open("notes/hello.txt")
        defer { engine.close(handle) }
        var buffer = [UInt8](repeating: 0, count: 256)
        let n = try buffer.withUnsafeMutableBytes { try engine.read(handle, offset: 0, into: $0) }
        XCTAssertEqual(Data(buffer[0..<n]), payload)

        // Plaintext file names must never appear in the ciphertext directory.
        let cipherNames = try FileManager.default.contentsOfDirectory(atPath: tempDir.path)
        XCTAssertFalse(cipherNames.contains { $0.contains("notes") || $0.contains("hello") })
    }

    func testReturnedScryptHashUnlocksTheVault() throws {
        let hash = try GocryptfsEngine.createVault(
            at: tempDir, password: "hash-unlock-pw", scryptLogN: Self.fastLogN)

        // Directly mount using the returned hash upon creation without re-deriving.
        let engine = try GocryptfsEngine(cipherDir: tempDir, credential: .scryptHash(hash))
        defer { engine.shutdown() }
        XCTAssertEqual(try engine.list("/").map(\.name), [".fseventsd"])
    }

    func testWrongPasswordIsRejected() throws {
        try GocryptfsEngine.createVault(at: tempDir, password: "the-real-one", scryptLogN: Self.fastLogN)
        XCTAssertThrowsError(
            try GocryptfsEngine(cipherDir: tempDir, credential: .password("not-the-real-one"))
        ) { error in
            XCTAssertEqual(error as? VaultError, .authFailed)
        }
    }

    // MARK: - Rejection Paths

    func testEmptyPasswordIsRefusedAndWritesNothing() throws {
        XCTAssertThrowsError(
            try GocryptfsEngine.createVault(at: tempDir, password: "", scryptLogN: Self.fastLogN)
        ) { XCTAssertEqual($0 as? VaultError, .emptyPassword) }

        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: tempDir.path), [],
                       "A rejected vault creation should not leave any residual files")
    }

    func testExistingVaultIsNeverOverwritten() throws {
        try GocryptfsEngine.createVault(at: tempDir, password: "first-pw", scryptLogN: Self.fastLogN)
        let original = try Data(contentsOf: conf(tempDir))

        XCTAssertThrowsError(
            try GocryptfsEngine.createVault(at: tempDir, password: "second-pw", scryptLogN: Self.fastLogN)
        ) { XCTAssertEqual($0 as? VaultError, .vaultAlreadyExists) }

        XCTAssertEqual(try Data(contentsOf: conf(tempDir)), original,
                       "Existing gocryptfs.conf must remain unchanged — overwriting it destroys all ciphertext")
        // Original password can still unlock it.
        let engine = try GocryptfsEngine(cipherDir: tempDir, credential: .password("first-pw"))
        engine.shutdown()
    }

    func testNonEmptyDirectoryIsRefused() throws {
        let stray = tempDir.appendingPathComponent("my-taxes.pdf")
        try Data("not encrypted".utf8).write(to: stray)

        XCTAssertThrowsError(
            try GocryptfsEngine.createVault(at: tempDir, password: "pw", scryptLogN: Self.fastLogN)
        ) { XCTAssertEqual($0 as? VaultError, .directoryNotEmpty) }

        XCTAssertTrue(FileManager.default.fileExists(atPath: stray.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: conf(tempDir).path))
    }

    func testDSStoreDoesNotBlockCreation() throws {
        // Finder creates .DS_Store when navigating; user considers directory empty.
        try Data([0]).write(to: tempDir.appendingPathComponent(".DS_Store"))
        try GocryptfsEngine.createVault(at: tempDir, password: "ds-store-pw", scryptLogN: Self.fastLogN)
        XCTAssertTrue(FileManager.default.fileExists(atPath: conf(tempDir).path))
    }

    func testMissingDirectoryIsRefused() throws {
        let missing = tempDir.appendingPathComponent("does-not-exist")
        XCTAssertThrowsError(
            try GocryptfsEngine.createVault(at: missing, password: "pw", scryptLogN: Self.fastLogN)
        ) { XCTAssertEqual($0 as? VaultError, .invalidCipherDir) }
    }

    func testFileInsteadOfDirectoryIsRefused() throws {
        let file = tempDir.appendingPathComponent("a-file")
        try Data("x".utf8).write(to: file)
        XCTAssertThrowsError(
            try GocryptfsEngine.createVault(at: file, password: "pw", scryptLogN: Self.fastLogN)
        ) { XCTAssertEqual($0 as? VaultError, .invalidCipherDir) }
    }

    /// Upstream ScryptKDF.DeriveKey invokes `os.Exit` when N < 2^10, and an `os.Exit` inside
    /// a c-archive terminates the entire host process (previously crashing the FSKit extension).
    /// This test completing and reporting an error while keeping the process alive proves the guard remains effective.
    func testOutOfRangeScryptLogNIsRejectedWithoutKillingTheProcess() throws {
        for bad: Int32 in [1, 9, 32, 64, -1] {
            XCTAssertThrowsError(
                try GocryptfsEngine.createVault(at: tempDir, password: "pw", scryptLogN: bad),
                "logN=\(bad) should be rejected"
            ) { XCTAssertEqual($0 as? VaultError, .invalidScryptLogN, "logN=\(bad)") }
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: tempDir.path), [])
    }
}

final class PasswordStrengthTests: XCTestCase {
    func testTooShort() {
        XCTAssertEqual(PasswordStrength.evaluate(""), .tooShort)
        XCTAssertEqual(PasswordStrength.evaluate("a"), .tooShort)
        XCTAssertEqual(PasswordStrength.evaluate("Ab3"), .tooShort)
        XCTAssertEqual(PasswordStrength.evaluate(String(repeating: "a", count: 3)), .tooShort)
    }

    func testRepeatedCharactersDoNotCountAsLength() {
        // 12 'a' characters appear long enough, but carry virtually no entropy.
        XCTAssertEqual(PasswordStrength.evaluate(String(repeating: "a", count: 12)), .weak)
    }

    func testLongerAndMoreVariedScoresHigher() {
        let short = PasswordStrength.evaluate("abcdefgh")
        let mixed = PasswordStrength.evaluate("Abcd3fgh!")
        let long = PasswordStrength.evaluate("correct-horse-battery-staple-42")
        XCTAssertLessThan(short, long)
        XCTAssertLessThanOrEqual(short, mixed)
        XCTAssertEqual(long, .strong)
    }

    func testEveryStrengthHasUserFacingText() {
        for strength in PasswordStrength.allCases {
            XCTAssertFalse(strength.label.isEmpty)
            XCTAssertFalse(strength.advice.isEmpty)
        }
    }
}
