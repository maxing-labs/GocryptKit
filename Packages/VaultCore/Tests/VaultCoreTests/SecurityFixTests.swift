import XCTest
@testable import VaultCore

final class VaultCredentialPayloadTests: XCTestCase {

    // MARK: - Serialization round-trip

    func testPasswordRoundTrip() throws {
        let original = VaultCredentialPayload.password("hunter2")
        let data = original.serialize()
        let restored = try XCTUnwrap(VaultCredentialPayload.deserialize(from: data))
        XCTAssertEqual(data[0], 0x56) // 'V'
        XCTAssertEqual(data[1], 0x43) // 'C'
        XCTAssertEqual(data[2], 0x50) // 'P'
        XCTAssertEqual(data[3], 0x31) // '1'
        XCTAssertEqual(data[4], 0x01) // tag: password
        let len = (UInt16(data[5]) << 8) | UInt16(data[6])
        XCTAssertEqual(len, 7) // "hunter2".utf8.count
        if case .password(let pwd) = restored {
            XCTAssertEqual(pwd, "hunter2")
        } else {
            XCTFail("Expected .password, got \(restored)")
        }
    }

    func testScryptHashRoundTrip() throws {
        let hash = Data(repeating: 0xAB, count: 32)
        let original = VaultCredentialPayload.scryptHash(hash)
        let data = original.serialize()
        let restored = try XCTUnwrap(VaultCredentialPayload.deserialize(from: data))
        XCTAssertEqual(data[0...3], Data([0x56, 0x43, 0x50, 0x31]))
        XCTAssertEqual(data[4], 0x02) // tag: scryptHash
        let len = (UInt16(data[5]) << 8) | UInt16(data[6])
        XCTAssertEqual(len, 32)
        if case .scryptHash(let h) = restored {
            XCTAssertEqual(h, hash)
        } else {
            XCTFail("Expected .scryptHash, got \(restored)")
        }
    }

    func testEmptyPasswordRoundTrip() throws {
        let original = VaultCredentialPayload.password("")
        let data = original.serialize()
        let restored = try XCTUnwrap(VaultCredentialPayload.deserialize(from: data))
        let len = (UInt16(data[5]) << 8) | UInt16(data[6])
        XCTAssertEqual(len, 0)
        if case .password(let pwd) = restored {
            XCTAssertEqual(pwd, "")
        } else {
            XCTFail("Expected .password, got \(restored)")
        }
    }

    func testUnicodePasswordRoundTrip() throws {
        let original = VaultCredentialPayload.password("密码🔐")
        let data = original.serialize()
        let restored = try XCTUnwrap(VaultCredentialPayload.deserialize(from: data))
        if case .password(let pwd) = restored {
            XCTAssertEqual(pwd, "密码🔐")
        } else {
            XCTFail("Expected .password, got \(restored)")
        }
    }

    // MARK: - Type confusion prevention

    /// A 32-byte scrypt hash that happens to be valid UTF-8 must NOT
    /// be misinterpreted as a password. This is the exact bug that
    /// the tagged protocol was designed to prevent.
    func testValidUTF8HashNotMisidentifiedAsPassword() throws {
        // "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" is 32 bytes of valid ASCII/UTF-8
        let sneakyHash = Data("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345".utf8)
        XCTAssertEqual(sneakyHash.count, 32)
        // Verify the old heuristic would misidentify this
        XCTAssertNotNil(String(data: sneakyHash, encoding: .utf8),
                        "Precondition: this hash IS valid UTF-8")

        // With the tagged protocol, it's correctly identified as scryptHash
        let payload = VaultCredentialPayload.scryptHash(sneakyHash)
        let data = payload.serialize()
        let restored = try XCTUnwrap(VaultCredentialPayload.deserialize(from: data))
        if case .scryptHash(let h) = restored {
            XCTAssertEqual(h, sneakyHash)
        } else {
            XCTFail("Expected .scryptHash, got \(restored)")
        }
    }

    // MARK: - Rejection of invalid data

    func testDeserializeTooShort() {
        XCTAssertNil(VaultCredentialPayload.deserialize(from: Data()))
        XCTAssertNil(VaultCredentialPayload.deserialize(from: Data([0x56])))
        XCTAssertNil(VaultCredentialPayload.deserialize(from: Data([0x56, 0x43])))
        XCTAssertNil(VaultCredentialPayload.deserialize(from: Data([0x56, 0x43, 0x50])))
        XCTAssertNil(VaultCredentialPayload.deserialize(from: Data([0x56, 0x43, 0x50, 0x31]))) // 4B
        XCTAssertNil(VaultCredentialPayload.deserialize(from: Data([0x56, 0x43, 0x50, 0x31, 0x01]))) // 5B
        XCTAssertNil(VaultCredentialPayload.deserialize(from: Data([0x56, 0x43, 0x50, 0x31, 0x01, 0x00]))) // 6B
    }

    func testDeserializeBadMagic() {
        let data = Data([0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04]) + Data("test".utf8)
        XCTAssertNil(VaultCredentialPayload.deserialize(from: data))
    }

    func testDeserializeOldGCMagicRejected() {
        // Old GC01 format: [0x47, 0x43, 0x01, 0x01] + "test"
        let oldData = Data([0x47, 0x43, 0x01, 0x01]) + Data("test".utf8)
        XCTAssertNil(VaultCredentialPayload.deserialize(from: oldData))
    }

    func testDeserializeUnknownTag() {
        let data = Data([0x56, 0x43, 0x50, 0x31, 0xFF, 0x00, 0x04]) + Data("test".utf8)
        XCTAssertNil(VaultCredentialPayload.deserialize(from: data))
    }

    func testDeserializeTruncatedPayload() {
        // Declares 10 bytes, but only provides 4
        let data = Data([0x56, 0x43, 0x50, 0x31, 0x01, 0x00, 0x0A]) + Data("test".utf8)
        XCTAssertNil(VaultCredentialPayload.deserialize(from: data))
    }

    func testDeserializeTrailingGarbage() {
        // Declares 4 bytes, but has 4 bytes + 4 extra bytes
        let data = Data([0x56, 0x43, 0x50, 0x31, 0x01, 0x00, 0x04]) + Data("testmore".utf8)
        XCTAssertNil(VaultCredentialPayload.deserialize(from: data))
    }

    /// Legacy untagged data must be rejected.
    func testLegacyUntaggedDataRejected() {
        // Raw scrypt hash (old format)
        let rawHash = Data(repeating: 0xDE, count: 32)
        XCTAssertNil(VaultCredentialPayload.deserialize(from: rawHash))

        // Raw UTF-8 password (old format)
        let rawPassword = Data("mypassword".utf8)
        XCTAssertNil(VaultCredentialPayload.deserialize(from: rawPassword))
    }

    /// Fuzzing / boundary tests for malformed lengths
    func testDeserializeHugeLengthOverflow() {
        // Declares 65535 bytes, only 1 byte payload
        let data = Data([0x56, 0x43, 0x50, 0x31, 0x01, 0xFF, 0xFF, 0x41])
        XCTAssertNil(VaultCredentialPayload.deserialize(from: data))
    }

    func testScryptHashInvalidLengthRejected() {
        // tag 0x02 (scryptHash) requires exactly 32 bytes.
        // Declares 16 bytes:
        let shortHash = Data([0x56, 0x43, 0x50, 0x31, 0x02, 0x00, 0x10]) + Data(repeating: 0xAA, count: 16)
        XCTAssertNil(VaultCredentialPayload.deserialize(from: shortHash))

        // Declares 33 bytes:
        let longHash = Data([0x56, 0x43, 0x50, 0x31, 0x02, 0x00, 0x21]) + Data(repeating: 0xAA, count: 33)
        XCTAssertNil(VaultCredentialPayload.deserialize(from: longHash))
    }
}

// MARK: - Vault.canonicalKey Tests

final class VaultCanonicalKeyTests: XCTestCase {

    func testResolvesVarToPrivateVar() {
        // /var is a symlink to /private/var on macOS
        let key1 = Vault.canonicalKey(path: "/var/tmp")
        let key2 = Vault.canonicalKey(path: "/private/var/tmp")
        XCTAssertEqual(key1, key2)
    }

    func testResolvesTmpToPrivateTmp() {
        // /tmp is a symlink to /private/tmp on macOS
        let key1 = Vault.canonicalKey(path: "/tmp")
        let key2 = Vault.canonicalKey(path: "/private/tmp")
        XCTAssertEqual(key1, key2)
    }

    func testNormalizesTrailingSlash() {
        let key1 = Vault.canonicalKey(path: "/tmp/")
        let key2 = Vault.canonicalKey(path: "/tmp")
        XCTAssertEqual(key1, key2)
    }

    func testNormalizesDotComponents() {
        let key1 = Vault.canonicalKey(path: "/tmp/./foo/../bar")
        let key2 = Vault.canonicalKey(path: "/tmp/bar")
        XCTAssertEqual(key1, key2)
    }

    func testNonExistentPathFallsBackToNormalize() {
        // A path that definitely doesn't exist
        let key = Vault.canonicalKey(path: "/nonexistent_\(UUID().uuidString)/vault")
        XCTAssertFalse(key.isEmpty)
        XCTAssertTrue(key.hasPrefix("/"))
    }
}

// MARK: - MountRecordStore Tests

final class MountRecordStoreTests: XCTestCase {
    func testRememberAndForgetRoundTrip() {
        let defaults = UserDefaults(suiteName: "test.mount.records.\(UUID().uuidString)")!
        defer { defaults.removePersistentDomain(forName: defaults.description) }

        let cipherDir = URL(fileURLWithPath: "/tmp/my-cipher")
        let mountPoint = URL(fileURLWithPath: "/tmp/my-mount")

        MountRecordStore.rememberCipherDir(cipherDir, for: mountPoint, userDefaults: defaults)
        let found = MountRecordStore.cipherDir(for: mountPoint, userDefaults: defaults)
        XCTAssertEqual(found, Vault.canonicalKey(path: cipherDir.path))

        let forgotten = MountRecordStore.forgetCipherDir(for: mountPoint, userDefaults: defaults)
        XCTAssertEqual(forgotten, Vault.canonicalKey(path: cipherDir.path))

        let afterForget = MountRecordStore.cipherDir(for: mountPoint, userDefaults: defaults)
        XCTAssertNil(afterForget)
    }
}
