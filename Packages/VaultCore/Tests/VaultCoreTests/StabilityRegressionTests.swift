import XCTest
import VaultCore

/// Engine stability regressions exercised through the C ABI the extension uses.
final class StabilityRegressionTests: XCTestCase {
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

    private func write(_ path: String, _ data: Data, at offset: UInt64 = 0) throws {
        let h = try engine.openWrite(path)
        defer { engine.close(h) }
        XCTAssertEqual(try data.withUnsafeBytes { try engine.write(h, offset: offset, from: $0) }, data.count)
    }

    private func read(_ path: String, at offset: UInt64 = 0, count: Int = 16384) throws -> Data {
        let h = try engine.open(path)
        defer { engine.close(h) }
        var buffer = Data(count: count)
        let n = try buffer.withUnsafeMutableBytes { try engine.read(h, offset: offset, into: $0) }
        return buffer.prefix(n)
    }

    /// A write beyond EOF must pad the old partial last block; otherwise that block
    /// sits mid-file and fails authentication (EIO) after a remount.
    func testWritePastEOFKeepsFirstBlockReadable() throws {
        try write("f", Data("head\n".utf8))
        let tail = Data(repeating: 84, count: 4096)
        try write("f", tail, at: 1 << 20)
        engine.shutdown()
        engine = try GocryptfsEngine(cipherDir: directory, credential: .password(password))
        XCTAssertEqual(try read("f", count: 5), Data("head\n".utf8))
        XCTAssertEqual(try read("f", at: 1 << 20, count: 4096), tail)
    }

    /// F-6: unmounting while callbacks are still running must not crash the process.
    func testShutdownDuringIO() throws {
        try write("r", Data(repeating: 114, count: 200_000))
        for _ in 0..<10 {
            let local = try GocryptfsEngine(cipherDir: directory, credential: .password(password))
            let group = DispatchGroup()
            let flag = NSLock()
            nonisolated(unsafe) var stopped = false
            for _ in 0..<4 {
                DispatchQueue.global().async(group: group) {
                    var buffer = Data(count: 65536)
                    while true {
                        flag.lock(); let done = stopped; flag.unlock()
                        if done { break }
                        if let h = try? local.open("r") {
                            _ = try? buffer.withUnsafeMutableBytes { try local.read(h, offset: 0, into: $0) }
                            local.close(h)
                        }
                        _ = local.cipherPath("r")
                    }
                }
            }
            Thread.sleep(forTimeInterval: 0.02)
            local.shutdown()
            Thread.sleep(forTimeInterval: 0.02)
            flag.lock(); stopped = true; flag.unlock()
            group.wait()
        }
    }

    /// F-7: a planted gocryptfs.diriv must not be read without bound or trusted.
    func testHostileDirIVIsRejected() throws {
        try engine.mkdir("big")
        let dir = try XCTUnwrap(engine.cipherPath("big"))
        let diriv = dir + "/gocryptfs.diriv"
        try FileManager.default.removeItem(atPath: diriv)
        XCTAssertTrue(FileManager.default.createFile(atPath: diriv, contents: nil))
        let handle = try XCTUnwrap(FileHandle(forWritingAtPath: diriv))
        try handle.truncate(atOffset: 512 << 20)  // sparse
        try handle.close()
        XCTAssertNil(engine.cipherPath("big/child"))
    }
}
