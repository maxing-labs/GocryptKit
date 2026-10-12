import XCTest
@testable import VaultCore

/// F-13: quitting must not force-unmount on its own, and must leave other users' volumes alone.
final class QuitUnmountTests: XCTestCase {
    private func entry(_ name: String, type: String = MountTable.gocryptfsTypeName, owner: uid_t = 501) -> MountTable.Entry {
        MountTable.Entry(fileSystemType: type, source: "file:///vaults/\(name)/", mountPoint: "/mnt/\(name)", ownerUID: owner)
    }

    func testBusyVolumeIsReportedAndNeverForced() {
        let entries = [entry("idle"), entry("busy"), entry("broken")]
        var calls: [(String, Bool)] = []
        let outcome = QuitUnmount.attempt(entries) { entry, force in
            calls.append((entry.mountPoint, force))
            if entry.mountPoint == "/mnt/busy" { throw UnmountError.parse(code: 1, message: "umount: /mnt/busy: Resource busy") }
            if entry.mountPoint == "/mnt/broken" { throw UnmountError.generic(code: 1, message: "not currently mounted") }
        }
        XCTAssertEqual(calls.map(\.0), ["/mnt/idle", "/mnt/busy", "/mnt/broken"])
        XCTAssertFalse(calls.contains { $0.1 }, "quit forced an unmount without asking")
        XCTAssertEqual(outcome.busy, [entries[1]])
        XCTAssertEqual(outcome.failed, [entries[2]])
        XCTAssertFalse(outcome.allUnmounted)
    }

    func testForceIsOnlyAppliedWhenRequested() {
        let busy = [entry("busy")]
        var forced: [Bool] = []
        let outcome = QuitUnmount.attempt(busy, force: true) { _, force in forced.append(force) }
        XCTAssertEqual(forced, [true])
        XCTAssertTrue(outcome.allUnmounted)
    }

    /// P-3: one volume busy, another failing for a different reason. Forcing only
    /// the busy one let the app quit with the other still mounted, unreported.
    func testQuitWaitsForAVolumeThatFailedForAnotherReason() {
        let busy = entry("busy"), broken = entry("broken")
        var mounted = [busy, broken]
        let first = QuitUnmount.attempt(mounted) { entry, force in
            if entry == busy && !force { throw UnmountError.parse(code: 1, message: "umount: /mnt/busy: Resource busy") }
            if entry == broken { throw UnmountError.generic(code: 1, message: "timed out") }
            mounted.removeAll { $0 == entry }
        }.settled(stillMounted: mounted)
        XCTAssertFalse(first.canQuitByForcing, "force offered although the app cannot quit afterwards")

        // Even if the busy one is forced, the volume that failed earlier keeps the app running.
        let forced = QuitUnmount.attempt(first.busy, force: true) { entry, _ in
            mounted.removeAll { $0 == entry }
        }.settled(stillMounted: mounted)
        XCTAssertFalse(forced.allUnmounted)
        XCTAssertEqual(forced.failed, [broken])
    }

    /// P-3: the live mount table decides, not the error a call happened to report.
    func testSettledOutcomeFollowsTheMountTable() {
        let busy = entry("busy"), gone = entry("gone"), late = entry("late")
        let outcome = QuitUnmount.Outcome(busy: [busy], failed: [gone])
        let settled = outcome.settled(stillMounted: [busy, late])
        XCTAssertEqual(settled.busy, [busy])
        XCTAssertEqual(settled.failed, [late], "a volume mounted meanwhile was ignored")
        XCTAssertFalse(settled.canQuitByForcing)
        XCTAssertTrue(outcome.settled(stillMounted: []).allUnmounted)
        XCTAssertTrue(QuitUnmount.Outcome(busy: [busy]).canQuitByForcing)
    }

    func testOnlyOwnMountsAreSelected() {
        let entries = [entry("mine", owner: 501), entry("theirs", owner: 502),
                       entry("disk", type: "apfs", owner: 501)]
        let mine = MountTable.gocryptfsMounts(in: entries, ownedBy: 501)
        XCTAssertEqual(mine.values.map(\.mountPoint), ["/mnt/mine"])
        let everyone = MountTable.gocryptfsMounts(in: entries, ownedBy: nil)
        XCTAssertEqual(Set(everyone.values.map(\.mountPoint)), ["/mnt/mine", "/mnt/theirs"])
    }

    func testLiveMountTableReportsOwners() {
        // The root volume always exists and is mounted by root.
        let root = MountTable.entries().first { $0.mountPoint == "/" }
        XCTAssertEqual(root?.ownerUID, 0)
    }
}
