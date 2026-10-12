import Foundation
import FSKit
import VaultCore
import XCTest

/// I-2: a rename rewrites an item's path, name and parent while other FSKit
/// callbacks read them. Run with Thread Sanitizer to see the race:
///   xcodebuild ... -scheme GocryptKitExtTests -enableThreadSanitizer YES \
///     TEST_RUNNER_TSAN_OPTIONS=halt_on_error=1 -only-testing:GocryptKitExtTests/PathRaceTests test
final class PathRaceTests: VolumeTestCase {

    func testRenameWhileOtherCallbacksReadThePath() throws {
        let dir = try create("d", type: .directory)
        let child = try create("f", in: dir)

        let stopLock = NSLock()
        nonisolated(unsafe) var stopped = false
        let group = DispatchGroup()
        for _ in 0..<4 {
            DispatchQueue.global().async(group: group) {
                while true {
                    stopLock.lock(); let done = stopped; stopLock.unlock()
                    if done { break }
                    _ = child.plainPath.count
                    _ = child.name.count
                    _ = child.parent?.inode
                    _ = try? self.attributes(of: child)
                    _ = dir.plainPath.count
                }
            }
        }
        for round in 0..<400 {
            try rename(dir, to: round % 2 == 0 ? "e" : "d")
        }
        stopLock.lock(); stopped = true; stopLock.unlock()
        group.wait()

        XCTAssertEqual(dir.plainPath, "d")
        XCTAssertEqual(child.plainPath, "d/f")
        XCTAssertEqual(try attributes(of: child).size, 0)
    }
}
