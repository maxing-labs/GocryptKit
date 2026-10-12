import Foundation
import FSKit
import VaultCore
import XCTest

/// Drives GocryptfsVolume's FSKit callbacks directly against a throwaway vault.
/// The volume replies synchronously, so the helpers can return the reply.
class VolumeTestCase: XCTestCase {
    var directory: URL!
    var engine: GocryptfsEngine!
    var volume: GocryptfsVolume!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let password = UUID().uuidString
        _ = try GocryptfsEngine.createVault(at: directory, password: password, scryptLogN: 10)
        engine = try GocryptfsEngine(cipherDir: directory, credential: .password(password))
        volume = try GocryptfsVolume(engine: engine, cipherURL: directory)
    }

    override func tearDownWithError() throws {
        engine?.shutdown()
        try FileManager.default.removeItem(at: directory)
    }

    func create(_ name: String, type: FSItem.ItemType = .file, in parent: GocryptfsItem? = nil,
                attributes: FSItem.SetAttributesRequest = FSItem.SetAttributesRequest()) throws -> GocryptfsItem {
        var result: Result<FSItem, Error>?
        volume.createItem(named: FSFileName(string: name), type: type, inDirectory: parent ?? volume.rootItem,
                          attributes: attributes) { item, _, error in
            result = item.map { .success($0) } ?? .failure(error ?? POSIXError(.EIO))
        }
        let item = try XCTUnwrap(result).get()  // rethrow the reply's error as is
        return try XCTUnwrap(item as? GocryptfsItem)
    }

    func lookup(_ name: String, in parent: GocryptfsItem? = nil) throws -> GocryptfsItem {
        var result: Result<FSItem, Error>?
        volume.lookupItem(named: FSFileName(string: name), inDirectory: parent ?? volume.rootItem) { item, _, error in
            result = item.map { .success($0) } ?? .failure(error ?? POSIXError(.EIO))
        }
        let item = try XCTUnwrap(result).get()  // rethrow the reply's error as is
        return try XCTUnwrap(item as? GocryptfsItem)
    }

    func open(_ item: GocryptfsItem, _ modes: FSVolume.OpenModes) throws {
        var error: Error?
        volume.openItem(item, modes: modes) { error = $0 }
        if let error { throw error }
    }

    func close(_ item: GocryptfsItem, keeping modes: FSVolume.OpenModes = []) throws {
        var error: Error?
        volume.closeItem(item, modes: modes) { error = $0 }
        if let error { throw error }
    }

    @discardableResult
    func write(_ text: String, to item: GocryptfsItem, at offset: off_t = 0) throws -> Int {
        var result: Result<Int, Error>?
        volume.write(contents: Data(text.utf8), to: item, at: offset) { count, error in
            result = error.map { .failure($0) } ?? .success(count)
        }
        return try XCTUnwrap(result).get()
    }

    func remove(_ item: GocryptfsItem, in parent: GocryptfsItem? = nil) throws {
        var error: Error?
        volume.removeItem(item, named: FSFileName(string: item.name), fromDirectory: parent ?? volume.rootItem) { error = $0 }
        if let error { throw error }
    }

    func rename(_ item: GocryptfsItem, to name: String, over: GocryptfsItem? = nil) throws {
        var error: Error?
        volume.renameItem(item, inDirectory: volume.rootItem, named: FSFileName(string: item.name),
                          to: FSFileName(string: name), inDirectory: volume.rootItem, overItem: over) { _, e in error = e }
        if let error { throw error }
    }

    func attributes(of item: GocryptfsItem) throws -> FSItem.Attributes {
        let request = FSItem.GetAttributesRequest()
        request.wantedAttributes = [.size, .linkCount, .mode, .type, .fileID, .parentID, .uid, .gid, .flags,
                                    .allocSize, .modifyTime, .accessTime, .changeTime, .birthTime]
        var result: Result<FSItem.Attributes, Error>?
        volume.getAttributes(request, of: item) { attrs, error in
            result = attrs.map { .success($0) } ?? .failure(error ?? POSIXError(.EIO))
        }
        return try XCTUnwrap(result).get()
    }

    @discardableResult
    func setAttributes(_ request: FSItem.SetAttributesRequest, on item: GocryptfsItem) throws -> FSItem.Attributes {
        var result: Result<FSItem.Attributes, Error>?
        volume.setAttributes(request, on: item) { attrs, error in
            result = attrs.map { .success($0) } ?? .failure(error ?? POSIXError(.EIO))
        }
        return try XCTUnwrap(result).get()
    }

    /// Whether the plaintext path currently has a backing ciphertext entry.
    func exists(_ plain: String) -> Bool {
        guard let path = engine.cipherPath(plain) else { return false }
        return FileManager.default.fileExists(atPath: path)
    }

    /// Content of the file currently at `plain`, read through a fresh handle.
    func content(of plain: String) throws -> String {
        let h = try engine.open(plain)
        defer { engine.close(h) }
        var data = Data(count: 1 << 16)
        let count = try data.withUnsafeMutableBytes { try engine.read(h, offset: 0, into: $0) }
        return String(decoding: data.prefix(count), as: UTF8.self)
    }

    func posixCode(_ error: Error) -> POSIXError.Code? {
        (error as? POSIXError)?.code
    }
}
