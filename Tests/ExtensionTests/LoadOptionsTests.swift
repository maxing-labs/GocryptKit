import XCTest

/// F-15: mount options are matched exactly, and none of them can name a Keychain account.
final class LoadOptionsTests: XCTestCase {
    private typealias LoadOptions = GocryptfsFileSystem.LoadOptions

    func testCommaJoinedOptionsFromSbinMount() {
        let parsed = LoadOptions.parse(["ro,rdonly,volname=Tax Docs_READ_ONLY"])
        XCTAssertEqual(parsed, LoadOptions(volumeName: "Tax Docs_READ_ONLY", isReadOnly: true))
        XCTAssertEqual(LoadOptions.parse(["-o", "volname=Plain"]), LoadOptions(volumeName: "Plain", isReadOnly: false))
        XCTAssertEqual(LoadOptions.parse(["RO"]).isReadOnly, true)
        XCTAssertEqual(LoadOptions.parse([]), LoadOptions())
    }

    func testLegacyVaultAccountOptionIsIgnored() {
        // `-o vault=<account>` used to select (and on failure delete) an arbitrary Keychain account.
        let parsed = LoadOptions.parse(["vault=/Users/someone/other-vault,volname=mine"])
        XCTAssertEqual(parsed, LoadOptions(volumeName: "mine", isReadOnly: false))
        XCTAssertEqual(LoadOptions.parse(["nosuid,vault=abc"]), LoadOptions())
    }

    func testOnlyExactKeysAndFlagsMatch() {
        XCTAssertEqual(LoadOptions.parse(["xvolname=evil"]), LoadOptions())
        XCTAssertEqual(LoadOptions.parse(["volname"]), LoadOptions())
        XCTAssertEqual(LoadOptions.parse(["volname="]), LoadOptions())
        XCTAssertEqual(LoadOptions.parse(["rox", "readonlyish", "nro"]), LoadOptions())
        // A value may contain "=": only the first one separates key and value.
        XCTAssertEqual(LoadOptions.parse(["volname=a=b"]).volumeName, "a=b")
        // The first volume name wins, as before.
        XCTAssertEqual(LoadOptions.parse(["volname=first,volname=second"]).volumeName, "first")
    }
}
