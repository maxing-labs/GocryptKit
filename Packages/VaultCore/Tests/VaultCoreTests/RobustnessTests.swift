import XCTest
@testable import VaultCore

final class RobustnessTests: XCTestCase {
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
            .deletingLastPathComponent() // GocryptfsKit
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

    // MARK: - 1. File Block Boundary Tests (0 bytes, 4096 bytes, 4097 bytes)

    func testBlockBoundarySizes() throws {
        let engine = try GocryptfsEngine(cipherDir: tempDir, credential: .password("test"))
        defer { engine.shutdown() }

        // Case A: 0 bytes empty file
        let zeroPath = "empty_zero.bin"
        let zeroWrite = try engine.openWrite(zeroPath)
        engine.close(zeroWrite)

        let zeroRead = try engine.open(zeroPath)
        var zeroBuf = [UInt8](repeating: 0, count: 16)
        let zeroBytes = try zeroBuf.withUnsafeMutableBytes {
            try engine.read(zeroRead, offset: 0, into: $0)
        }
        engine.close(zeroRead)
        XCTAssertEqual(zeroBytes, 0, "0-byte file must return 0 bytes read")

        // Case B: Exactly 4096 bytes (1 complete gocryptfs block)
        let exactBlockPath = "exact_4096.bin"
        let data4096 = Data((0..<4096).map { UInt8($0 & 0xFF) })
        let exactWrite = try engine.openWrite(exactBlockPath)
        let written4096 = try data4096.withUnsafeBytes {
            try engine.write(exactWrite, offset: 0, from: $0)
        }
        XCTAssertEqual(written4096, 4096)
        engine.close(exactWrite)

        let exactRead = try engine.open(exactBlockPath)
        var readBuf4096 = [UInt8](repeating: 0, count: 4096)
        let readBytes4096 = try readBuf4096.withUnsafeMutableBytes {
            try engine.read(exactRead, offset: 0, into: $0)
        }
        engine.close(exactRead)
        XCTAssertEqual(readBytes4096, 4096)
        XCTAssertEqual(Data(readBuf4096), data4096)

        // Case C: Exactly 4097 bytes (cross-block: 4096 + 1 byte)
        let crossBlockPath = "cross_4097.bin"
        let data4097 = Data((0..<4097).map { UInt8(($0 * 7) & 0xFF) })
        let crossWrite = try engine.openWrite(crossBlockPath)
        let written4097 = try data4097.withUnsafeBytes {
            try engine.write(crossWrite, offset: 0, from: $0)
        }
        XCTAssertEqual(written4097, 4097)
        engine.close(crossWrite)

        let crossRead = try engine.open(crossBlockPath)
        var readBuf4097 = [UInt8](repeating: 0, count: 4097)
        let readBytes4097 = try readBuf4097.withUnsafeMutableBytes {
            try engine.read(crossRead, offset: 0, into: $0)
        }
        engine.close(crossRead)
        XCTAssertEqual(readBytes4097, 4097)
        XCTAssertEqual(Data(readBuf4097), data4097)
    }

    // MARK: - 2. Tampering & Bit-rot Injection (Ciphertext Corruption Detection)

    func testTamperedCiphertextBitRotRejection() throws {
        let engine = try GocryptfsEngine(cipherDir: tempDir, credential: .password("test"))
        defer { engine.shutdown() }

        let fileName = "tamper_test.bin"
        let originalData = Data(repeating: 0x42, count: 2048)
        let writeHandle = try engine.openWrite(fileName)
        _ = try originalData.withUnsafeBytes {
            try engine.write(writeHandle, offset: 0, from: $0)
        }
        engine.close(writeHandle)

        // Locate ciphertext on disk
        guard let cipherPath = engine.cipherPath(fileName) else {
            XCTFail("Failed to resolve cipherPath for \(fileName)")
            return
        }
        let cipherURL = URL(fileURLWithPath: cipherPath)
        XCTAssertTrue(FileManager.default.fileExists(atPath: cipherURL.path), "Ciphertext file must exist on disk")

        var cipherData = try Data(contentsOf: cipherURL)
        XCTAssertGreaterThan(cipherData.count, 64, "Ciphertext file must have header and payload")

        // Intentionally flip one bit in the middle of ciphertext payload (offset 50)
        cipherData[50] ^= 0x01
        try cipherData.write(to: cipherURL)

        // Attempting to read corrupted ciphertext must fail AES-GCM tag verification and throw an error
        let readHandle = try engine.open(fileName)
        defer { engine.close(readHandle) }

        var readBuffer = [UInt8](repeating: 0, count: 2048)
        XCTAssertThrowsError(
            try readBuffer.withUnsafeMutableBytes {
                _ = try engine.read(readHandle, offset: 0, into: $0)
            },
            "Reading bit-corrupted ciphertext must throw verification error rather than returning corrupt data"
        )
    }

    // MARK: - 3. Concurrent Multi-Threaded Read/Write Stress Test

    func testConcurrentReadWriteStress() throws {
        let engine = try GocryptfsEngine(cipherDir: tempDir, credential: .password("test"))
        defer { engine.shutdown() }

        let iterations = 8
        let payloadSize = 32 * 1024 // 32 KB per worker

        DispatchQueue.concurrentPerform(iterations: iterations) { i in
            let path = "concurrent_worker_\(i).dat"
            let pattern = UInt8(i * 17 + 3)
            let workerData = Data(repeating: pattern, count: payloadSize)

            do {
                let writeHandle = try engine.openWrite(path)
                let written = try workerData.withUnsafeBytes {
                    try engine.write(writeHandle, offset: 0, from: $0)
                }
                XCTAssertEqual(written, payloadSize)
                engine.close(writeHandle)

                let readHandle = try engine.open(path)
                var readBuffer = [UInt8](repeating: 0, count: payloadSize)
                let readBytes = try readBuffer.withUnsafeMutableBytes {
                    try engine.read(readHandle, offset: 0, into: $0)
                }
                engine.close(readHandle)

                XCTAssertEqual(readBytes, payloadSize)
                XCTAssertEqual(Data(readBuffer), workerData)
            } catch {
                XCTFail("Concurrent worker \(i) failed with error: \(error)")
            }
        }
    }

    // MARK: - 4. Typed Mount & Unmount Error Parsing

    func testTypedMountAndUnmountErrorParsing() {
        // Mount errors
        XCTAssertEqual(
            MountError.parse(code: 16, message: "Resource busy"),
            .busyOrAlreadyMounted
        )
        XCTAssertEqual(
            MountError.parse(code: 13, message: "Permission denied"),
            .permissionDenied
        )
        XCTAssertEqual(
            MountError.parse(code: 2, message: "No such file or directory"),
            .pathNotFound
        )
        XCTAssertEqual(
            MountError.parse(code: 66, message: "Directory not empty"),
            .mountPointNotEmpty
        )
        XCTAssertEqual(
            MountError.parse(code: 1, message: "Module com.xwei.GocryptKit.AppEx is disabled!"),
            .extensionDisabled
        )
        XCTAssertEqual(
            MountError.parse(code: 1, message: "Couldn't communicate with a helper application"),
            .extensionStartingUp
        )
        XCTAssertEqual(
            MountError.parse(code: 1, message: "Authentication failed"),
            .invalidPasswordOrMasterKey
        )

        // Unmount errors
        let busyUnmount = UnmountError.parse(code: 16, message: "Resource busy")
        XCTAssertTrue(busyUnmount.isBusy)

        let inUseUnmount = UnmountError.parse(code: 0, message: "Volume is in use")
        XCTAssertTrue(inUseUnmount.isBusy)

        let normalUnmountErr = UnmountError.parse(code: 1, message: "Unknown disk error")
        XCTAssertFalse(normalUnmountErr.isBusy)
    }
}
