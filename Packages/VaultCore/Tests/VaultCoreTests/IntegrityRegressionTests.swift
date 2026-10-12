import XCTest
import VaultCore

final class IntegrityRegressionTests: XCTestCase {
    private var directory: URL!
    private var password: String!
    private var engine: GocryptfsEngine!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        password = UUID().uuidString
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        _ = try GocryptfsEngine.createVault(at: directory, password: password, scryptLogN: 10)
        engine = try GocryptfsEngine(cipherDir: directory, credential: .password(password))
    }

    override func tearDownWithError() throws {
        engine?.shutdown()
        try FileManager.default.removeItem(at: directory)
        password = nil
    }

    private func reopen() throws {
        engine.shutdown()
        engine = try GocryptfsEngine(cipherDir: directory, credential: .password(password))
    }

    private func write(_ path: String, _ data: Data) throws {
        let h = try engine.openWrite(path)
        defer { engine.close(h) }
        XCTAssertEqual(try data.withUnsafeBytes { try engine.write(h, offset: 0, from: $0) }, data.count)
    }

    private func read(_ path: String) throws -> Data {
        let h = try engine.open(path)
        defer { engine.close(h) }
        return try readHandle(h)
    }

    private func readHandle(_ h: Int32) throws -> Data {
        var buffer = Data(count: 16384)
        let count = try buffer.withUnsafeMutableBytes { try engine.read(h, offset: 0, into: $0) }
        return buffer.prefix(count)
    }

    func testRewriteAfterZeroTruncate() throws {
        let h = try engine.openWrite("f")
        let initial = Data(repeating: 65, count: 10000)
        _ = try initial.withUnsafeBytes { try engine.write(h, offset: 0, from: $0) }
        try engine.truncate("f", size: 0)
        let replacement = Data("replacement content".utf8)
        _ = try replacement.withUnsafeBytes { try engine.write(h, offset: 0, from: $0) }
        engine.close(h)
        try reopen()
        XCTAssertTrue(try read("f") == replacement)
        let path = try XCTUnwrap(engine.cipherPath("f"))
        let header = try Data(contentsOf: URL(fileURLWithPath: path)).prefix(2)
        XCTAssertTrue(header == Data([0, 2]))
    }

    func testOpenReaderSurvivesRewrite() throws {
        try write("f", Data(repeating: 65, count: 10000))
        let r = try engine.open("f")
        defer { engine.close(r) }
        _ = try readHandle(r)
        let w = try engine.openWrite("f")
        defer { engine.close(w) }
        // The old path API may choose a read-only handle. Retry only to expose B1 as well.
        var truncated = false
        for _ in 0..<40 where !truncated {
            do { try engine.truncate("f", size: 0); truncated = true } catch { }
        }
        XCTAssertTrue(truncated)
        let replacement = Data("replacement content".utf8)
        _ = try replacement.withUnsafeBytes { try engine.write(w, offset: 0, from: $0) }
        XCTAssertTrue(try readHandle(r) == replacement)
        XCTAssertTrue(try read("f") == replacement)
    }

    func testTruncateWithReaderOpen() throws {
        try write("f", Data("initial".utf8))
        for _ in 0..<40 {
            let r = try engine.open("f")
            let w = try engine.openWrite("f")
            defer { engine.close(r); engine.close(w) }
            try engine.truncate("f", size: 0)
        }
        try reopen()
        XCTAssertTrue(try read("f").isEmpty)
    }

    private func swap() throws {
        for path in ["A", "A/x", "Old", "Old/x"] { try engine.mkdir(path) }
        try write("A/x/f", Data("original".utf8))
        try write("Old/x/f", Data("incoming".utf8))
        _ = try read("A/x/f")
        try engine.rename(from: "A", to: "Tmp")
        try engine.rename(from: "Old", to: "A")
    }

    func testDirectorySwapWrite() throws {
        try swap()
        try write("A/x/f", Data("updated!".utf8))
        try reopen()
        XCTAssertTrue(try read("A/x/f") == Data("updated!".utf8))
        XCTAssertTrue(try read("Tmp/x/f") == Data("original".utf8))
    }

    func testDirectorySwapRemove() throws {
        try swap()
        try engine.remove("A/x/f")
        try reopen()
        XCTAssertThrowsError(try engine.open("A/x/f"))
        XCTAssertTrue(try read("Tmp/x/f") == Data("original".utf8))
    }

    func testRecreateDirectoryImmediately() throws {
        try engine.mkdir("D")
        XCTAssertThrowsError(try engine.open("D/probe"))
        try engine.rmdir("D")
        try engine.mkdir("D")
        try write("D/f", Data("new file".utf8))
        try reopen()
        XCTAssertTrue(try read("D/f") == Data("new file".utf8))
    }
}
