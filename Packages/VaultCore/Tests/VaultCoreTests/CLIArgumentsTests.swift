import XCTest
import VaultCore

/// F-19: strict command-line parsing and stdin password handling.
final class CLIArgumentsTests: XCTestCase {

    func testWellFormedCommands() throws {
        XCTAssertEqual(try CLIArguments.parse(["init", "/v", "--scryptn", "10", "--password-stdin"]),
                       .initVault(cipherDir: "/v", scryptLogN: 10, passwordFromStdin: true))
        XCTAssertEqual(try CLIArguments.parse(["init", "/v"]),
                       .initVault(cipherDir: "/v", scryptLogN: nil, passwordFromStdin: false))
        XCTAssertEqual(try CLIArguments.parse(["mount", "/v", "/m", "--password-stdin"]),
                       .mount(cipherDir: "/v", mountPoint: "/m", readOnly: false, passwordFromStdin: true))
        for flag in ["--readonly", "-r", "--ro"] {
            XCTAssertEqual(try CLIArguments.parse(["mount", flag, "/v", "/m"]),
                           .mount(cipherDir: "/v", mountPoint: "/m", readOnly: true, passwordFromStdin: false))
        }
        XCTAssertEqual(try CLIArguments.parse(["umount", "-f", "/m"]), .unmount(mountPoint: "/m", force: true))
        XCTAssertEqual(try CLIArguments.parse(["umount", "/m", "--force"]), .unmount(mountPoint: "/m", force: true))
        XCTAssertEqual(try CLIArguments.parse(["umount", "/m"]), .unmount(mountPoint: "/m", force: false))
        XCTAssertEqual(try CLIArguments.parse(["status"]), .status)
        XCTAssertEqual(try CLIArguments.parse(["version"]), .version)
        XCTAssertEqual(try CLIArguments.parse(["mount", "--", "-odd", "/m"]),
                       .mount(cipherDir: "-odd", mountPoint: "/m", readOnly: false, passwordFromStdin: false))
    }

    func testMisspelledReadOnlyFlagIsAnErrorNotAWritableMount() {
        for typo in ["--read-only", "--readOnly", "-ro", "--rdonly", "-R"] {
            XCTAssertThrowsError(try CLIArguments.parse(["mount", "/v", "/m", typo])) { error in
                XCTAssertTrue(error.localizedDescription.contains(typo), "error should name \(typo)")
            }
        }
    }

    func testUnknownOptionsAndStrayArgumentsAreRejected() {
        XCTAssertThrowsError(try CLIArguments.parse(["umount", "/m", "--forse"]))
        XCTAssertThrowsError(try CLIArguments.parse(["init", "/v", "--scrypt", "10"]))
        XCTAssertThrowsError(try CLIArguments.parse(["init", "/v", "--scryptn"]))
        XCTAssertThrowsError(try CLIArguments.parse(["init", "/v", "--scryptn", "ten"]))
        XCTAssertThrowsError(try CLIArguments.parse(["mount", "/v"]))
        XCTAssertThrowsError(try CLIArguments.parse(["mount", "/v", "/m", "/extra"]))
        XCTAssertThrowsError(try CLIArguments.parse(["umount"]))
        XCTAssertThrowsError(try CLIArguments.parse(["status", "--verbose"]))
        XCTAssertThrowsError(try CLIArguments.parse(["frobnicate"]))
    }

    func testRemovedPasswordFlagKeepsItsExplanation() {
        XCTAssertThrowsError(try CLIArguments.parse(["init", "/v", "--password", "secret"])) { error in
            XCTAssertTrue(error.localizedDescription.contains("removed for security reasons"))
        }
        XCTAssertThrowsError(try CLIArguments.parse(["mount", "/v", "/m", "--password", "secret"]))
    }

    /// D-8: `--password=secret` was reported as "Unknown option: --password=secret",
    /// printing the password to stderr. The value of an unknown option is never echoed.
    func testOptionValuesAreNotEchoed() {
        XCTAssertThrowsError(try CLIArguments.parse(["mount", "/v", "/m", "--password=secret"])) { error in
            XCTAssertTrue(error.localizedDescription.contains("removed for security reasons"))
            XCTAssertFalse(error.localizedDescription.contains("secret"))
        }
        XCTAssertThrowsError(try CLIArguments.parse(["init", "/v", "--pasword=secret"])) { error in
            XCTAssertTrue(error.localizedDescription.contains("--pasword"))
            XCTAssertFalse(error.localizedDescription.contains("secret"))
        }
    }

    func testStdinPasswordStripsExactlyOneTrailingNewline() throws {
        XCTAssertEqual(try StdinPassword.parse(Data("secret\n".utf8)), "secret")
        XCTAssertEqual(try StdinPassword.parse(Data("secret".utf8)), "secret")
        XCTAssertEqual(try StdinPassword.parse(Data("secret\n\n".utf8)), "secret\n")
        XCTAssertEqual(try StdinPassword.parse(Data("\nsecret\n".utf8)), "\nsecret")
        XCTAssertEqual(try StdinPassword.parse(Data(" spaced \n".utf8)), " spaced ")
    }

    func testStdinPasswordRejectsEmptyOverlongAndInvalidInput() {
        XCTAssertThrowsError(try StdinPassword.parse(Data())) { XCTAssertEqual($0 as? StdinPassword.Failure, .empty) }
        XCTAssertThrowsError(try StdinPassword.parse(Data("\n".utf8))) { XCTAssertEqual($0 as? StdinPassword.Failure, .empty) }
        let limit = StdinPassword.maximumBytes
        XCTAssertEqual(try StdinPassword.parse(Data(repeating: 112, count: limit) + Data("\n".utf8)).utf8.count, limit)
        XCTAssertThrowsError(try StdinPassword.parse(Data(repeating: 112, count: limit + 1))) {
            XCTAssertEqual($0 as? StdinPassword.Failure, .tooLong)
        }
        XCTAssertThrowsError(try StdinPassword.parse(Data([0xff, 0xfe, 0x0a]))) {
            XCTAssertEqual($0 as? StdinPassword.Failure, .notUTF8)
        }
        XCTAssertGreaterThan(StdinPassword.readLimit, limit + 1)
    }
}
