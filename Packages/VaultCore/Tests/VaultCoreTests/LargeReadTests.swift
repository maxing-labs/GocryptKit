import XCTest
@testable import VaultCore

final class LargeReadTests: XCTestCase {
    var tempDir: URL!

    override func setUpWithError() throws {
        let fileManager = FileManager.default
        tempDir = fileManager.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fileManager.createDirectory(at: tempDir, withIntermediateDirectories: true)

        let fixtureURL = URL(fileURLWithPath: #file)
            .deletingLastPathComponent() // VaultCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // VaultCore
            .deletingLastPathComponent() // Packages
            .deletingLastPathComponent() // Repository Root
            .appendingPathComponent("Tests/fixtures/v1.3")

        let items = try fileManager.contentsOfDirectory(at: fixtureURL, includingPropertiesForKeys: nil)
        for item in items {
            let dest = tempDir.appendingPathComponent(item.lastPathComponent)
            try fileManager.copyItem(at: item, to: dest)
        }
    }

    override func tearDownWithError() throws {
        if let dir = tempDir {
            try? FileManager.default.removeItem(at: dir)
        }
    }

    func testLargeChunkAndConcurrentRead() throws {
        let engine = try GocryptfsEngine(cipherDir: tempDir, credential: .password("test"))
        defer { engine.shutdown() }

        // 1. Generate 2 MiB test payload (larger than 128 KiB MAX_KERNEL_WRITE)
        let totalSize = 2 * 1024 * 1024 // 2MB
        var testData = Data(count: totalSize)
        testData.withUnsafeMutableBytes { (ptr: UnsafeMutableRawBufferPointer) in
            for i in 0..<totalSize {
                ptr[i] = UInt8((i * 31 + 17) & 0xFF)
            }
        }

        let filePath = "large_video_sim.bin"
        let writeHandle = try engine.openWrite(filePath)
        let written = try testData.withUnsafeBytes { rawBuf in
            try engine.write(writeHandle, offset: 0, from: rawBuf)
        }
        XCTAssertEqual(written, totalSize)
        engine.close(writeHandle)

        // 2. Open for reading
        let readHandle = try engine.open(filePath)
        defer { engine.close(readHandle) }

        // Test A: 512 KiB single read (previously failed with 128 KiB truncation / EIO)
        let chunkSize512K = 512 * 1024
        var buf512K = [UInt8](repeating: 0, count: chunkSize512K)
        let read512K = try buf512K.withUnsafeMutableBytes { rawBuf in
            try engine.read(readHandle, offset: 0, into: rawBuf)
        }
        XCTAssertEqual(read512K, chunkSize512K)
        XCTAssertEqual(Data(buf512K), testData.prefix(chunkSize512K))

        // Test B: 1 MiB single read at 512 KiB offset
        let chunkSize1M = 1024 * 1024
        var buf1M = [UInt8](repeating: 0, count: chunkSize1M)
        let read1M = try buf1M.withUnsafeMutableBytes { rawBuf in
            try engine.read(readHandle, offset: UInt64(chunkSize512K), into: rawBuf)
        }
        XCTAssertEqual(read1M, chunkSize1M)
        XCTAssertEqual(Data(buf1M), testData.subdata(in: chunkSize512K..<(chunkSize512K + chunkSize1M)))

        // Test C: Partial read across EOF (request 512 KiB at totalSize - 100 KiB)
        let remainingBytes = 100 * 1024
        let offsetNearEOF = totalSize - remainingBytes
        var bufNearEOF = [UInt8](repeating: 0, count: chunkSize512K)
        let readNearEOF = try bufNearEOF.withUnsafeMutableBytes { rawBuf in
            try engine.read(readHandle, offset: UInt64(offsetNearEOF), into: rawBuf)
        }
        XCTAssertEqual(readNearEOF, remainingBytes)
        XCTAssertEqual(Data(bufNearEOF.prefix(readNearEOF)), testData.suffix(remainingBytes))

        // Test D: Read exactly at EOF
        var bufAtEOF = [UInt8](repeating: 0, count: 4096)
        let readAtEOF = try bufAtEOF.withUnsafeMutableBytes { rawBuf in
            try engine.read(readHandle, offset: UInt64(totalSize), into: rawBuf)
        }
        XCTAssertEqual(readAtEOF, 0)

        // Test E: Read past EOF
        let readPastEOF = try bufAtEOF.withUnsafeMutableBytes { rawBuf in
            try engine.read(readHandle, offset: UInt64(totalSize + 1024), into: rawBuf)
        }
        XCTAssertEqual(readPastEOF, 0)

        // Test F: Concurrent multi-threaded reads (simulating video demuxer)
        DispatchQueue.concurrentPerform(iterations: 30) { index in
            let randomOffset = (index * 65536) % (totalSize - chunkSize512K)
            var threadBuf = [UInt8](repeating: 0, count: chunkSize512K)
            do {
                let n = try threadBuf.withUnsafeMutableBytes { rawBuf in
                    try engine.read(readHandle, offset: UInt64(randomOffset), into: rawBuf)
                }
                XCTAssertEqual(n, chunkSize512K)
                let expected = testData.subdata(in: randomOffset..<(randomOffset + chunkSize512K))
                XCTAssertEqual(Data(threadBuf), expected)
            } catch {
                XCTFail("Concurrent read failed at iteration \(index): \(error)")
            }
        }
    }
}
