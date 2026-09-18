import XCTest
@testable import VaultCore

final class WriteTests: XCTestCase {
    var tempDir: URL!

    override func setUpWithError() throws {
        let fileManager = FileManager.default
        tempDir = fileManager.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fileManager.createDirectory(at: tempDir, withIntermediateDirectories: true)

        // Copy v1.3 fixture to tempDir
        let fixtureURL = URL(fileURLWithPath: #file)
            .deletingLastPathComponent() // VaultCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // VaultCore
            .deletingLastPathComponent() // Packages
            .deletingLastPathComponent() // GocryptKit
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

    func testCreateWriteReadRenameRemove() throws {
        let engine = try GocryptfsEngine(cipherDir: tempDir, credential: .password("test"))
        defer { engine.shutdown() }

        // 1. Create directory
        try engine.mkdir("new_folder")
        let entries1 = try engine.list("")
        XCTAssertTrue(entries1.contains(where: { $0.name == "new_folder" && $0.isDirectory }))

        // 2. Create and write file
        let filePath = "new_folder/created.txt"
        let handle = try engine.openWrite(filePath)
        let writeData = "Hello M2 Write Path!".data(using: .utf8)!
        let written = try writeData.withUnsafeBytes { rawBuf in
            try engine.write(handle, offset: 0, from: rawBuf)
        }
        XCTAssertEqual(written, writeData.count)
        engine.close(handle)

        // 3. Verify read
        let readHandle = try engine.open(filePath)
        var readBuf = [UInt8](repeating: 0, count: 64)
        let bytesRead = try readBuf.withUnsafeMutableBytes { rawBuf in
            try engine.read(readHandle, offset: 0, into: rawBuf)
        }
        engine.close(readHandle)
        XCTAssertEqual(bytesRead, writeData.count)
        let readString = String(decoding: readBuf[0..<bytesRead], as: Unicode.UTF8.self)
        XCTAssertEqual(readString, "Hello M2 Write Path!")

        // 4. Rename file
        let renamedPath = "new_folder/renamed.txt"
        try engine.rename(from: filePath, to: renamedPath)
        let entries2 = try engine.list("new_folder")
        XCTAssertTrue(entries2.contains(where: { $0.name == "renamed.txt" }))
        XCTAssertFalse(entries2.contains(where: { $0.name == "created.txt" }))

        // 5. Remove file
        try engine.remove(renamedPath)
        let entries3 = try engine.list("new_folder")
        XCTAssertFalse(entries3.contains(where: { $0.name == "renamed.txt" }))

        // 6. Remove directory
        try engine.rmdir("new_folder")
        let entries4 = try engine.list("")
        XCTAssertFalse(entries4.contains(where: { $0.name == "new_folder" }))
    }

    func testLongNameCreateWriteReadRemove() throws {
        let engine = try GocryptfsEngine(cipherDir: tempDir, credential: .password("test"))
        defer { engine.shutdown() }

        let longName = "longname_" + String(repeating: "x", count: 200)
        let handle = try engine.openWrite(longName)
        let writeData = "Long Name Content".data(using: .utf8)!
        let written = try writeData.withUnsafeBytes { rawBuf in
            try engine.write(handle, offset: 0, from: rawBuf)
        }
        XCTAssertEqual(written, writeData.count)
        engine.close(handle)

        // Open existing long name file for reading
        let readHandle = try engine.open(longName)
        var readBuf = [UInt8](repeating: 0, count: 64)
        let bytesRead = try readBuf.withUnsafeMutableBytes { rawBuf in
            try engine.read(readHandle, offset: 0, into: rawBuf)
        }
        engine.close(readHandle)
        XCTAssertEqual(bytesRead, writeData.count)
        XCTAssertEqual(String(decoding: readBuf[0..<bytesRead], as: Unicode.UTF8.self), "Long Name Content")

        // Open existing long name file again in write mode (to verify EEXIST handling)
        let appendHandle = try engine.openWrite(longName)
        engine.close(appendHandle)

        // List directory should find the long name
        let entries = try engine.list("")
        XCTAssertTrue(entries.contains(where: { $0.name == longName }))

        // Remove long name
        try engine.remove(longName)
        let entriesAfter = try engine.list("")
        XCTAssertFalse(entriesAfter.contains(where: { $0.name == longName }))
    }
}
