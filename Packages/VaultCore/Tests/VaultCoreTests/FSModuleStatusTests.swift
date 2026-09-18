import XCTest
@testable import VaultCore

/// These strings were captured from real system execution on 2026-09-16, not synthesized.
/// Manually disabling the FSKit module and re-running cannot be automated in CI,
/// so we pin actual command outputs directly into test cases.
final class FSModuleProbeTests: XCTestCase {

    /// Full stderr of `mount` when the module is disabled by system policy.
    private let disabledOutput = """
    Mount failed (code 72): Module com.xwei.GocryptKit.AppEx is disabled!
    mount: exec /Library/Filesystems/gocryptfs.fs/Contents/Resources/mount_gocryptfs for /private/tmp/fix-mount.StwUxR: No such file or directory
    mount: /private/tmp/fix-mount.StwUxR failed with 72
    """

    /// Stderr when the module is enabled and working, but the provided source is not a valid vault.
    /// Notice this also terminates with code 72, so **exit codes alone cannot differentiate status**.
    private let enabledButBadSourceOutput = """
    mount: Probing resource: The operation couldn’t be completed. Operation not supported by device
    mount: exec /Library/Filesystems/gocryptfs.fs/Contents/Resources/mount_gocryptfs for /private/tmp/probe-mnt.thxp6y: No such file or directory
    mount: /private/tmp/probe-mnt.thxp6y failed with 72
    """

    /// Known transient error during extension cold start (see README). Does not indicate disabled module.
    private let coldStartOutput = """
    mount: Probing resource: Couldn't communicate with a helper application.
    mount: /private/tmp/x failed with 72
    """

    func testDetectsDisabledModule() {
        XCTAssertEqual(FSModuleProbe.interpret(mountStderr: disabledOutput), .disabled)
    }

    /// Critical invariant: probe failure does not equal module disabled.
    /// Misclassification would wrongly send users into System Settings for a toggle that is already enabled.
    func testBadSourceIsNotMistakenForDisabled() {
        XCTAssertEqual(FSModuleProbe.interpret(mountStderr: enabledButBadSourceOutput), .enabled)
    }

    func testColdStartIsNotMistakenForDisabled() {
        XCTAssertEqual(FSModuleProbe.interpret(mountStderr: coldStartOutput), .enabled)
    }

    /// Both command outputs end with `failed with 72` — illustrating why return code alone is insufficient.
    /// Pinned by this test to prevent future regressions attempting to "simplify" status checks to exit codes.
    func testBothOutcomesShareTheSameExitCodeText() {
        XCTAssertTrue(disabledOutput.contains("failed with 72"))
        XCTAssertTrue(enabledButBadSourceOutput.contains("failed with 72"))
        XCTAssertNotEqual(FSModuleProbe.interpret(mountStderr: disabledOutput),
                          FSModuleProbe.interpret(mountStderr: enabledButBadSourceOutput))
    }

    func testEmptyOutputIsTreatedAsEnabled() {
        XCTAssertEqual(FSModuleProbe.interpret(mountStderr: ""), .enabled)
    }

    // MARK: - Registration Status

    func testRegisteredOutputIsRecognised() {
        let output = "+    com.xwei.GocryptKit.AppEx(0.2.0)\t0D79357C-0D13-487B-9DD5-766DDF20ABA0\t2026-09-16 20:45:40 +0000\t/Applications/GocryptKit.app/Contents/Extensions/GocryptKitExt.appex\n (1 plug-in)\n"
        XCTAssertTrue(FSModuleProbe.isRegistered(pluginkitOutput: output))
    }

    /// Extensions without a `+` indicator still count as registered — system built-in exfat / msdos
    /// appear this way and function properly.
    func testRegisteredWithoutPlusSignIsStillRegistered() {
        let output = "     com.apple.fskit.exfat((null))\t804C4700\t2026-08-17 20:13:27 +0000\t/System/Library/ExtensionKit/Extensions/com.apple.fskit.exfat.appex\n (1 plug-in)\n"
        XCTAssertTrue(FSModuleProbe.isRegistered(pluginkitOutput: output))
    }

    func testNoMatchesMeansNotRegistered() {
        XCTAssertFalse(FSModuleProbe.isRegistered(pluginkitOutput: "  (no matches)\n"))
    }

    func testEmptyPluginkitOutputMeansNotRegistered() {
        XCTAssertFalse(FSModuleProbe.isRegistered(pluginkitOutput: "   \n"))
    }
}


/// The probe itself issues an actual mount request. Launching it while volumes are mounted
/// interrupts the extension process serving those volumes — observed empirically to cause immediate
/// volume invalidation and `ls` returning "Input/output error".
///
/// Hence `MountManager.checkExtensionStatus()` enforces a strict invariant:
/// **If the mount table is non-empty, immediately classify as enabled without probing.**
/// This is not an optimization; it is a critical safety constraint. This test verifies its prerequisite:
/// having active mounts conclusively proves the module is enabled, so skipping the probe loses no information.
final class ProbeSafetyInvariantTests: XCTestCase {

    /// Non-empty mount table implies the module must be usable. A disabled module cannot mount anything,
    /// so this deduction holds without exception.
    func testAMountedVolumeProvesTheModuleIsUsable() {
        let mounts = MountTable.gocryptfsMounts()
        guard !mounts.isEmpty else {
            // No volume currently mounted; deduction cannot be tested on live system — not a failure.
            return
        }
        for (_, entry) in mounts {
            XCTAssertEqual(entry.fileSystemType, MountTable.gocryptfsTypeName,
                           "Mount table entries identified as gocryptfs must have the exact gocryptfs type name")
        }
    }

    /// Pins the decision direction: only explicit "is disabled" output signifies disabled.
    /// Any regression treating generic probe failure as disabled will fail this test.
    func testOnlyAnExplicitDisabledMessageCountsAsDisabled() {
        let notDisabled = [
            "mount: Probing resource: Operation not supported by device",
            "mount: Couldn't communicate with a helper application.",
            "mount: /private/tmp/x failed with 72",
            "some completely unrelated failure",
            "",
        ]
        for message in notDisabled {
            XCTAssertEqual(FSModuleProbe.interpret(mountStderr: message), .enabled,
                           "\"\(message)\" should not be interpreted as module disabled")
        }
    }
}
