import Foundation
import FSKit
import VaultCore
import XCTest

final class OpenCloseTests: XCTestCase {
    private var directory: URL!
    private var engine: GocryptfsEngine!
    private var volume: GocryptfsVolume!
    private var item: GocryptfsItem!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let password = UUID().uuidString
        _ = try GocryptfsEngine.createVault(at: directory, password: password, scryptLogN: 10)
        engine = try GocryptfsEngine(cipherDir: directory, credential: .password(password))
        volume = try GocryptfsVolume(engine: engine, cipherURL: directory)
        try seed("original")
        item = GocryptfsItem(id: .invalid, plainPath: "f", name: "f", itemType: .file, inode: 1)
    }

    override func tearDownWithError() throws {
        item?.forceClose(using: engine)
        engine?.shutdown()
        try FileManager.default.removeItem(at: directory)
    }

    private func seed(_ text: String) throws {
        let h = try engine.openWrite("f")
        defer { engine.close(h) }
        let data = Data(text.utf8)
        _ = try data.withUnsafeBytes { try engine.write(h, offset: 0, from: $0) }
    }

    private func open(_ modes: FSVolume.OpenModes) throws {
        var error: Error?
        volume.openItem(item, modes: modes) { error = $0 }
        if let error { throw error }
    }

    private func close(keeping modes: FSVolume.OpenModes) throws {
        var error: Error?
        volume.closeItem(item, modes: modes) { error = $0 }
        if let error { throw error }
    }

    private func read(_ h: Int32) throws -> Data {
        var data = Data(count: 64)
        let count = try data.withUnsafeMutableBytes { try engine.read(h, offset: 0, into: $0) }
        return data.prefix(count)
    }

    func testLastCloseReleasesWriterAfterRepeatedOpen() throws {
        try open([.write])
        try open([.write])
        try close(keeping: [])
        try engine.remove("f")
        try seed("replacement")
        let h = try item.acquireWriteHandle(using: engine)
        defer { item.releaseWriteHandle(using: engine) }
        let data = Data("new content".utf8)
        _ = try data.withUnsafeBytes { try engine.write(h, offset: 0, from: $0) }
        let r = try engine.open("f")
        defer { engine.close(r) }
        XCTAssertTrue(try read(r) == data)
    }

    func testCloseKeepsReaderAfterWriteUpgrade() throws {
        try open([.read])
        try open([.write])
        try close(keeping: [.read])
        try engine.remove("f")
        try seed("replacement")
        let r = try item.acquireReadHandle(using: engine)
        defer { item.releaseReadHandle(using: engine) }
        XCTAssertTrue(try read(r) == Data("original".utf8))
        try close(keeping: [])
    }
}
